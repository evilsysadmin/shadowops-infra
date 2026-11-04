import base64
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from identity_staging_atlas_backup import BackupError, snapshot
from identity_staging_backup import decrypt_snapshot

class AtlasBackupTests(unittest.TestCase):
 def test_credentials_are_only_passed_in_stdin_and_snapshot_is_encrypted(self):
  cfg={'environment':'staging','host':'cluster.mongodb.net','username':'backup_fixture','password':'synthetic-secret-password-123','backup_key':base64.urlsafe_b64encode(b'k'*32).decode()}
  value={'schema':2,'environment':'staging','database':'shadowops_identity_staging','collections':{name:[] for name in ('pending_accounts','sessions','staging_cka_tokens','admin_inventory_audit','staging_application_access_history')}}
  def run(args,**kwargs):
   self.assertFalse(any(cfg['password'] in arg or cfg['username'] in arg for arg in args))
   self.assertNotIn(cfg['password'],str(kwargs['env']))
   self.assertIn(cfg['password'],kwargs['input'])
   self.assertIn('--read-only',args)
   self.assertIn('shadowops-identity-atlas-backup-'+'a'*24,args)
   return type('Result',(),{'returncode':0,'stdout':json.dumps(value)})()
  encrypted=snapshot(cfg,'shadowops-identity-atlas-backup-'+'a'*24,runner=run)
  self.assertNotIn(b'pending_accounts',encrypted)
  self.assertEqual(decrypt_snapshot(encrypted,cfg['backup_key']),value)
 def test_unsafe_host_or_authentication_never_starts_container(self):
  good={'environment':'staging','host':'cluster.mongodb.net','username':'backup_fixture','password':'synthetic-secret-password-123','backup_key':base64.urlsafe_b64encode(b'k'*32).decode()}
  for field,value in [('host','evil.example'),('host','cluster.mongodb.net.attacker.net'),('environment','production'),('username','identity_root'),('password','bad')]:
   cfg={**good,field:value}
   with self.subTest(field=field),self.assertRaises(BackupError):snapshot(cfg,'shadowops-identity-atlas-backup-'+'a'*24,runner=lambda *args,**kwargs:self.fail('unsafe configuration reached Docker'))

class AtlasNetworkOwnershipTests(unittest.TestCase):
 def test_temporary_network_removed_after_success_and_failure(self):
  import importlib.util
  path=Path(__file__).resolve().parents[1]/'host'/'identity-atlas-staging-backup.py'
  spec=importlib.util.spec_from_file_location('atlas_backup_host',path)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  calls=[]
  def command(args):calls.append(args)
  def capture(config,network):self.assertEqual(network,'shadowops-identity-atlas-backup-'+'b'*24);return b'encrypted'
  self.assertEqual(module.capture_snapshot({},command=command,capture=capture,nonce='b'*24),b'encrypted')
  self.assertEqual(calls[-1],['rm','shadowops-identity-atlas-backup-'+'b'*24])
  calls.clear()
  def failed(config,network):raise BackupError('failure')
  with self.assertRaises(BackupError):module.capture_snapshot({},command=command,capture=failed,nonce='c'*24)
  self.assertEqual(calls[-1],['rm','shadowops-identity-atlas-backup-'+'c'*24])

 def test_host_writes_encrypted_snapshot_and_receipt_without_sensitive_data(self):
  import importlib.util
  import tempfile
  from unittest.mock import patch
  path=Path(__file__).resolve().parents[1]/'host'/'identity-atlas-staging-backup.py'
  spec=importlib.util.spec_from_file_location('atlas_backup_host_for_test',path)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  cfg={'environment':'staging','host':'cluster.mongodb.net','username':'backup_fixture','password':'synthetic-secret-password-123','backup_key':base64.urlsafe_b64encode(b'k'*32).decode()}
  value={'schema':2,'environment':'staging','database':'shadowops_identity_staging','collections':{name:[] for name in ('pending_accounts','sessions','staging_cka_tokens','admin_inventory_audit','staging_application_access_history')}}
  from identity_staging_backup import encrypt_snapshot
  encrypted=encrypt_snapshot(value,cfg['backup_key'])
  with tempfile.TemporaryDirectory() as temp:
   state=Path(temp);directory=state/'atlas-backups'
   with patch.object(module,'STATE',state),patch.object(module,'DIRECTORY',directory),patch.object(module,'trusted'),patch.object(module,'private_config',return_value=cfg),patch.object(module,'capture_snapshot',return_value=encrypted),patch.object(module.os,'geteuid',return_value=0),patch.object(sys,'argv',['runner','backup']):
    self.assertEqual(module.main(),0)
   files=list(directory.glob('*.fernet'));self.assertEqual(len(files),1)
   self.assertEqual(decrypt_snapshot(files[0].read_bytes(),cfg['backup_key']),value)
   receipt=json.loads((state/'last-atlas-backup.json').read_text())
   self.assertEqual(receipt['backend'],'atlas')
   self.assertNotIn(cfg['password'],json.dumps(receipt))
