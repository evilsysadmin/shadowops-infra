import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from identity_staging_atlas_admission import require_recent_atlas_backup
from identity_staging_backup import BackupError, encrypt_snapshot

class AtlasBackupAdmissionTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.state=Path(self.temp.name);self.state.chmod(0o700)
  self.directory=self.state/'atlas-backups';self.directory.mkdir(mode=0o700)
  self.now=datetime.now(timezone.utc)
  self.config={'environment':'staging','host':'cluster.mongodb.net','username':'backup_user','password':'synthetic-password-12345','backup_key':base64.urlsafe_b64encode(b'k'*32).decode()}
  value={'schema':2,'environment':'staging','database':'shadowops_identity_staging','collections':{c:[] for c in ('pending_accounts','sessions','staging_cka_tokens','admin_inventory_audit','staging_application_access_history')}}
  self.encrypted=encrypt_snapshot(value,self.config['backup_key'])
  self.snapshot=self.directory/'fixture.fernet';self.snapshot.write_bytes(self.encrypted);self.snapshot.chmod(0o600)
  self.receipt={'schema':1,'environment':'staging','backend':'atlas','created_at':self.now.isoformat(),'cluster_sha256':hashlib.sha256(self.config['host'].encode()).hexdigest(),'sha256':hashlib.sha256(self.encrypted).hexdigest(),'encrypted_bytes':len(self.encrypted)}
  self.write_receipt()
 def write_receipt(self):
  path=self.state/'last-atlas-backup.json';path.write_text(json.dumps(self.receipt));path.chmod(0o600)
 def check(self,config=None):require_recent_atlas_backup(config or self.config,self.state,now=self.now,expected_uid=os.getuid())
 def test_accepts_recent_authenticated_snapshot_for_exact_cluster(self):self.check()
 def test_rejects_old_future_other_cluster_and_tampering(self):
  valid=dict(self.receipt)
  for field,value in [('created_at',(self.now-timedelta(hours=25)).isoformat()),('created_at',(self.now+timedelta(minutes=6)).isoformat()),('cluster_sha256','0'*64),('backend','local'),('sha256','1'*64),('encrypted_bytes',len(self.encrypted)+1)]:
   self.receipt={**valid,field:value};self.write_receipt()
   with self.subTest(field=field,value=value),self.assertRaises(BackupError):self.check()
  self.receipt=valid;self.write_receipt()
  self.snapshot.write_bytes(self.encrypted[:-1]+(b'A' if self.encrypted[-1:]!=b'A' else b'B'))
  with self.assertRaises(BackupError):self.check()
 def test_rejects_untrusted_modes_and_different_key(self):
  self.snapshot.chmod(0o644)
  with self.assertRaises(BackupError):self.check()
  self.snapshot.chmod(0o600)
  with self.assertRaises(BackupError):self.check({**self.config,'backup_key':base64.urlsafe_b64encode(b'x'*32).decode()})

 def test_returns_only_the_authenticated_matching_snapshot_for_rehearsal(self):
  admitted=require_recent_atlas_backup(self.config,self.state,now=self.now,expected_uid=os.getuid())
  self.assertEqual(admitted['sha256'],self.receipt['sha256'])
  self.assertEqual(admitted['snapshot']['schema'],2)
  self.assertEqual(admitted['cluster_sha256'],self.receipt['cluster_sha256'])
