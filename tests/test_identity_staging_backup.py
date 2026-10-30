from pathlib import Path
import copy
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cryptography.fernet import Fernet
import identity_staging_backup as backup


def snapshot():
 return {'schema':1,'environment':'staging','database':backup.DATABASE,'collections':{
  'pending_accounts':[{'_id':'11111111-1111-4111-8111-111111111111','environment':'staging','state':'active','credentials_disabled':False,'credential_hash':'synthetic-hash','recovery_digest':'synthetic-old-proof','session_version':{'$numberLong':'7'},'credential_version':{'$numberLong':'3'}}],
  'sessions':[{'digest':'synthetic-handle-digest'}],'staging_cka_tokens':[{'token_jti':'synthetic-token'}]}}


class BackupTests(unittest.TestCase):
 def test_real_encryption_authentication_and_independent_key(self):
  key=Fernet.generate_key();value=snapshot()
  encrypted=backup.encrypt_snapshot(value,key)
  self.assertNotIn(b'synthetic-hash',encrypted)
  self.assertEqual(backup.decrypt_snapshot(encrypted,key),value)
  for data,secret in [(encrypted[:-1]+b'x',key),(encrypted,Fernet.generate_key())]:
   with self.assertRaises(backup.BackupError):backup.decrypt_snapshot(data,secret)

 def test_restore_retains_uuid_but_removes_all_live_authentication(self):
  value=snapshot();original=copy.deepcopy(value)
  result=backup.quarantine_restore(value)
  self.assertEqual(value,original)
  row=result['collections']['pending_accounts'][0]
  self.assertEqual(row['_id'],value['collections']['pending_accounts'][0]['_id'])
  self.assertEqual(row['state'],'restore-review');self.assertTrue(row['credentials_disabled'])
  self.assertEqual(row['session_version'],{'$numberLong':'8'})
  self.assertEqual(row['credential_version'],{'$numberLong':'4'})
  self.assertNotIn('credential_hash',row);self.assertNotIn('recovery_digest',row)
  self.assertEqual(result['collections']['sessions'],[])
  self.assertEqual(result['collections']['staging_cka_tokens'],[])

 def test_cross_environment_and_corrupt_versions_cannot_be_restored(self):
  for mutate in [lambda v:v.update(environment='production'),lambda v:v.update(database='chronicles_staging'),lambda v:v['collections']['pending_accounts'][0].update(session_version={'$numberLong':'9223372036854775807'}),lambda v:v['collections']['pending_accounts'][0].update(environment='production')]:
   value=snapshot();mutate(value)
   with self.assertRaises(backup.BackupError):backup.quarantine_restore(value)


if __name__=='__main__':unittest.main()
