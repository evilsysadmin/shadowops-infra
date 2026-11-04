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

def snapshot_v2():
 value=snapshot();value['schema']=2
 subject=value['collections']['pending_accounts'][0]['_id']
 date={'$date':{'$numberLong':'1730000000000'}}
 value['collections']['staging_application_access_history']=[{'_id':subject+':chronicles','environment':'staging','subject':subject,'application':'chronicles','first_at':date,'last_at':date}]
 value['collections']['admin_inventory_audit']=[{'_id':'a'*32,'environment':'staging','actor':subject,'action':'list_accounts','at':date,'returned':{'$numberInt':'1'}}]
 return value


class AtlasBackupCredentialTests(unittest.TestCase):
 def test_refuses_unsafe_credentials_without_including_them_in_error(self):
  for username,password in [('identity_root','safe-test-password-1234'),('bad name','safe-test-password-1234'),('valid_user','short'),('valid_user','bad\npassword-with-control')]:
   with self.subTest(username=username), self.assertRaises(backup.BackupError) as failure:
    backup.atlas_export_script(username,password)
   self.assertNotIn(password,str(failure.exception))

class BackupTests(unittest.TestCase):
 def test_v2_preserves_history_and_audit_in_quarantine(self):
  value=snapshot_v2();key=Fernet.generate_key()
  value['collections']['pending_accounts'][0]['role']='admin'
  self.assertEqual(backup.decrypt_snapshot(backup.encrypt_snapshot(value,key),key),value)
  restored=backup.quarantine_restore(value)
  for name in backup.ADMIN_COLLECTIONS:self.assertEqual(restored['collections'][name],value['collections'][name])
  self.assertEqual(restored['collections']['sessions'],[])
  self.assertEqual(restored['collections']['staging_cka_tokens'],[])
  self.assertEqual(restored['collections']['pending_accounts'][0]['state'],'restore-review')
  self.assertEqual(restored['collections']['pending_accounts'][0]['role'],'user')

 def test_v2_rejects_bad_admin_records_and_missing_collections(self):
  for mutate in [lambda v:v['collections'].pop('admin_inventory_audit'),lambda v:v['collections']['staging_application_access_history'][0].update(environment='production'),lambda v:v['collections']['staging_application_access_history'][0].update(application='unknown'),lambda v:v['collections']['admin_inventory_audit'][0].update(actor='invalid'),lambda v:v['collections']['admin_inventory_audit'][0].update(returned=51),lambda v:v['collections']['staging_application_access_history'][0].update(last_at={'$date':{'$numberLong':'1'}})]:
   value=snapshot_v2();mutate(value)
   with self.assertRaises(backup.BackupError):backup.validate_snapshot(value)

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
