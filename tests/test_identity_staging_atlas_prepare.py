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
  original_fchown=os.fchown
  self.chown_patch=patch.object(prepare.os,'fchown',side_effect=lambda fd,uid,gid:original_fchown(fd,uid,os.getgid()))
  self.chown_patch.start()
  self.addCleanup(self.chown_patch.stop)
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

class AtlasDatabaseScopedPrepareTests(unittest.TestCase):
 def test_database_scoped_mode_requires_explicit_selection_and_is_separate(self):
  base='mongodb+srv://{}:synthetic-password-12345@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin'
  custody=prepare_atlas_custody(None,*(base.format(name) for name in ('app','inventory','backup')))
  service={'environment':'staging','mongo_uri':'local','admin_inventory_access_history':True}
  uid=os.getuid();real_chown=os.fchown
  with tempfile.TemporaryDirectory() as temp,patch.object(prepare.os,'fchown',side_effect=lambda fd,owner,group:real_chown(fd,owner,os.getgid())):
   directory=Path(temp)
   prepare.prepare_files(directory,service,custody,service_uid=uid,backup_uid=uid,database_scoped=True)
   saved=json.loads((directory/'atlas-service.json').read_text())
   self.assertEqual(saved['mongo_privilege_mode'],'database-scoped')
   self.assertNotIn('mongo_privilege_mode',service)
   with self.assertRaises(prepare.PrepareError):prepare.prepare_files(directory,service,custody,service_uid=uid,backup_uid=uid)

class AtlasInventoryRefreshTests(unittest.TestCase):
 def test_inactive_inventory_refresh_is_atomic_and_checkpointed(self):
  from identity_staging_atlas_custody import rotate_inventory_uri
  uid=os.getuid();real_chown=os.fchown
  original=prepare_atlas_custody(None,*(BASE.format(name) for name in ('app','inventory','backup')))
  updated=rotate_inventory_uri(original, original['application_uri'], original['inventory_uri'].replace('synthetic-password','rotated-password'), original['backup_uri'])
  service={'environment':'staging','mongo_uri':'local','admin_inventory_access_history':True}
  with tempfile.TemporaryDirectory() as temp,patch.object(prepare.os,'fchown',side_effect=lambda fd,owner,group:real_chown(fd,owner,os.getgid())):
   root=Path(temp)
   prepare.prepare_files(root,service,original,service_uid=uid,backup_uid=uid,database_scoped=True)
   before=(root/'atlas-service.json').read_bytes()
   backup=(root/'atlas-backup.json').read_bytes()
   with self.assertRaises(prepare.PrepareError):
    prepare.refresh_inventory_candidate(root,service,updated,service_uid=uid,backup_uid=uid,is_in_use=lambda _:True)
   self.assertEqual((root/'atlas-service.json').read_bytes(),before)
   with self.assertRaises(prepare.PrepareError):
    prepare.refresh_inventory_candidate(root,service,updated,service_uid=uid,backup_uid=uid)
   prepare.refresh_inventory_candidate(root,service,updated,service_uid=uid,backup_uid=uid,is_in_use=lambda _:False)
   self.assertEqual(json.loads((root/'atlas-service.json').read_text())['admin_inventory_mongo_uri'],updated['inventory_uri'])
   self.assertEqual((root/'atlas-backup.json').read_bytes(),backup)
   checkpoints=list(root.glob('.atlas-service-previous-*'))
   self.assertEqual(len(checkpoints),1)
   self.assertEqual(checkpoints[0].read_bytes(),before)
   self.assertEqual(stat.S_IMODE(checkpoints[0].stat().st_mode),0o400)
   prepare.refresh_inventory_candidate(root,service,updated,service_uid=uid,backup_uid=uid,is_in_use=lambda _:True)
   self.assertEqual(len(list(root.glob('.atlas-service-previous-*'))),1)

 def test_unrelated_configuration_change_is_rejected(self):
  from identity_staging_atlas_custody import rotate_inventory_uri
  uid=os.getuid();real_chown=os.fchown
  original=prepare_atlas_custody(None,*(BASE.format(name) for name in ('app','inventory','backup')))
  updated=rotate_inventory_uri(original, original['application_uri'], original['inventory_uri'].replace('synthetic-password','rotated-password'), original['backup_uri'])
  service={'environment':'staging','mongo_uri':'local','admin_inventory_access_history':True,'signing_seed':'original'}
  with tempfile.TemporaryDirectory() as temp,patch.object(prepare.os,'fchown',side_effect=lambda fd,owner,group:real_chown(fd,owner,os.getgid())):
   root=Path(temp)
   prepare.prepare_files(root,service,original,service_uid=uid,backup_uid=uid,database_scoped=True)
   before=(root/'atlas-service.json').read_bytes()
   changed=dict(service,signing_seed='different')
   with self.assertRaises(prepare.PrepareError):
    prepare.refresh_inventory_candidate(root,changed,updated,service_uid=uid,backup_uid=uid,is_in_use=lambda _:False)
   self.assertEqual((root/'atlas-service.json').read_bytes(),before)

class AtlasMountAdmissionTests(unittest.TestCase):
 def test_running_bind_mounts_and_hardlinks_block_candidate_refresh(self):
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);candidate=root/'atlas-service.json';candidate.write_text('fixture')
   link=root/'hardlink';os.link(candidate,link)
   ident='a'*64
   def runner_for(mount):
    def run(args, **kwargs):
     if args[1]=='ps': return SimpleNamespace(returncode=0,stdout=ident+'\n')
     return SimpleNamespace(returncode=0,stdout=json.dumps([mount])+'\n')
    return run
   for source in (str(candidate),str(root),str(link)):
    self.assertTrue(prepare.candidate_is_mounted(candidate,runner=runner_for({'Type':'bind','Source':source})))
   other=root/'unrelated';other.write_text('other')
   self.assertFalse(prepare.candidate_is_mounted(candidate,runner=runner_for({'Type':'bind','Source':str(other)})))
   with self.assertRaises(prepare.PrepareError):
    prepare.candidate_is_mounted(candidate,runner=runner_for({'Type':'bind','Source':str(root/'missing')}))
 def test_invalid_or_unavailable_docker_fails_closed(self):
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as temp:
   candidate=Path(temp)/'atlas-service.json';candidate.write_text('fixture')
   for result in (SimpleNamespace(returncode=1,stdout=''),SimpleNamespace(returncode=0,stdout='invalid-id\n')):
    with self.assertRaises(prepare.PrepareError):prepare.candidate_is_mounted(candidate,runner=lambda *a,**k:result)
