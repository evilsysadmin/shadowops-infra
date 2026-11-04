import copy
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from identity_staging_atlas_custody import prepare_atlas_custody
spec=importlib.util.spec_from_file_location('identity_atlas_prepare',ROOT/'host/identity-atlas-staging-prepare.py')
prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)

BASE='mongodb+srv://{}:synthetic-password-12345@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin'

class AtlasPrepareTests(unittest.TestCase):
 def setUp(self):
  self.custody=prepare_atlas_custody(None,*(BASE.format(name) for name in ('app','inventory','backup')))
  self.service={'environment':'staging','mongo_uri':'local','mongo_ca_pem':'old-ca','signing_seed':'synthetic-seed','tls_private_key_pem':'synthetic-key','consumers':{'chronicles':'fixture'},'admin_inventory_access_history':True}
 def test_separate_private_files_idempotence_and_no_overwrite(self):
  uid=os.getuid()
  with tempfile.TemporaryDirectory() as temp:
   directory=Path(temp);old=directory/'service.json';old.write_text(json.dumps(self.service));before=old.read_bytes()
   prepare.prepare_files(directory,self.service,self.custody,service_uid=uid,backup_uid=uid)
   app=directory/'atlas-service.json';backup=directory/'atlas-backup.json'
   self.assertEqual(old.read_bytes(),before)
   self.assertEqual(stat.S_IMODE(app.stat().st_mode),0o400)
   self.assertEqual(stat.S_IMODE(backup.stat().st_mode),0o400)
   self.assertEqual(json.loads(app.read_text())['mongo_uri'],self.custody['application_uri'])
   self.assertEqual(json.loads(backup.read_text())['backup_key'],self.custody['backup_key'])
   self.assertNotIn('backup_key',json.loads(app.read_text()))
   self.assertNotIn('signing_seed',json.loads(backup.read_text()))
   first=app.read_bytes(),backup.read_bytes()
   prepare.prepare_files(directory,self.service,self.custody,service_uid=uid,backup_uid=uid)
   self.assertEqual((app.read_bytes(),backup.read_bytes()),first)
   changed=copy.deepcopy(self.service);changed['signing_seed']='different'
   with self.assertRaises(prepare.PrepareError):prepare.prepare_files(directory,changed,self.custody,service_uid=uid,backup_uid=uid)
   self.assertEqual((app.read_bytes(),backup.read_bytes()),first)
 def test_no_history_or_symlink_is_rejected_without_modifying_target(self):
  uid=os.getuid()
  with tempfile.TemporaryDirectory() as temp:
   directory=Path(temp);target=directory/'target';target.write_text('unchanged')
   (directory/'atlas-service.json').symlink_to(target)
   with self.assertRaises(prepare.PrepareError):prepare.prepare_files(directory,self.service,self.custody,service_uid=uid,backup_uid=uid)
   self.assertEqual(target.read_text(),'unchanged')
  with tempfile.TemporaryDirectory() as temp:
   with self.assertRaises(prepare.PrepareError):prepare.prepare_files(Path(temp),{},self.custody,service_uid=uid,backup_uid=uid)
 def test_only_dedicated_atlas_secret_is_requested(self):
  data=__import__('base64').b64encode(json.dumps(self.custody).encode()).decode()
  calls=[]
  from types import SimpleNamespace
  client=SimpleNamespace(get_secret_bundle_by_name=lambda **kw:calls.append(kw) or SimpleNamespace(data=SimpleNamespace(secret_bundle_content=SimpleNamespace(content=data))))
  sdk=SimpleNamespace(auth=SimpleNamespace(signers=SimpleNamespace(InstancePrincipalsSecurityTokenSigner=lambda:'signer')),secrets=SimpleNamespace(SecretsClient=lambda **kw:client))
  with patch.dict(sys.modules,{'oci':sdk}):self.assertEqual(prepare.read_atlas_custody('vault-id'),self.custody)
  self.assertEqual(calls,[{'secret_name':'identity-staging-atlas-custody','vault_id':'vault-id','stage':'CURRENT'}])
