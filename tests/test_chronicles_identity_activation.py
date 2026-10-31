from __future__ import annotations
import base64
import json
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime,timezone,timedelta

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('chronicles_identity_host',ROOT/'host/chronicles-api-deploy.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
import chronicles_api_provision as provision
import identity_staging_provision as identity

SOC='soc1_'+base64.urlsafe_b64encode(b'E'*32).decode().rstrip('=')
BASE={'MONGO_URL':'mongodb://fixture:private@fixture/','JWT_SECRET':'j'*64,'INVITE_CODE':'fixture','TUNNEL_TOKEN':'t'*80}


class ActivationTests(unittest.TestCase):
 def test_recent_root_backup_receipt_is_required_for_activation(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'last-backup.json'
   receipt={'schema':1,'environment':'staging','created_at':datetime.now(timezone.utc).isoformat(),'encrypted_bytes':128,'sha256':'a'*64}
   path.write_text(json.dumps(receipt));host.verify_identity_backup(path,require_root=False)
   for change in [{'environment':'production'},{'created_at':(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()},{'created_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()},{'encrypted_bytes':0}]:
    path.write_text(json.dumps({**receipt,**change}))
    with self.assertRaises(host.ReleaseError):host.verify_identity_backup(path,require_root=False)

 def test_opt_in_proof_goes_only_to_staging_api_and_can_be_removed(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)
   values=host.parse_bundle(''.join(k+'='+v+'\n' for k,v in {**BASE,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC}.items()))
   host.write_runtime(values,path,host.STAGING)
   text=(path/'api.env').read_text()
   self.assertIn("ENABLE_SHADOWOPS_IDENTITY='true'",text)
   self.assertIn("SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL='"+SOC+"'",text)
   self.assertNotIn(SOC,(path/'tunnel.env').read_text())
   self.assertEqual((path/'api.env').stat().st_mode&0o777,0o600)
   host.write_runtime(BASE,path,host.STAGING)
   text=(path/'api.env').read_text()
   self.assertIn("ENABLE_SHADOWOPS_IDENTITY='false'",text)
   self.assertNotIn('SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL',text)
   self.assertIn("JWT_SECRET='"+BASE['JWT_SECRET']+"'",text)

 def test_production_and_malformed_credentials_stop_before_config_write(self):
  for target,credential in [(host.TARGETS['production'],SOC),(host.STAGING,'incorrect')]:
   with tempfile.TemporaryDirectory() as temp:
    path=Path(temp)
    with self.assertRaises(host.ReleaseError):
     host.write_runtime({**BASE,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':credential},path,target)
    self.assertFalse((path/'api.env').exists())

 def test_existing_consumer_configuration_is_preserved_without_rotation(self):
  text=''.join(k+'='+v+'\n' for k,v in {**BASE,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC}.items())
  read=[]
  sdk=SimpleNamespace(pagination=SimpleNamespace(list_call_get_all_results=lambda *a,**k:SimpleNamespace(data=[SimpleNamespace(lifecycle_state='ACTIVE')])),vault=SimpleNamespace(VaultsClient=lambda config:SimpleNamespace(list_secrets=None)),secrets=SimpleNamespace(SecretsClient=lambda config:SimpleNamespace(get_secret_bundle_by_name=lambda **k:read.append(k) or SimpleNamespace(data=SimpleNamespace(secret_bundle_content=SimpleNamespace(content=base64.b64encode(text.encode()).decode()))))))
  self.assertEqual(provision.central_credential('preserve',sdk,{},'vault','compartment'),SOC)
  self.assertEqual(read,[dict(secret_name='chronicles-staging-runtime-env',vault_id='vault',stage='CURRENT')])

 def test_enable_extracts_only_fixed_chronicles_consumer(self):
  with patch.object(identity,'load_existing',return_value={'consumers':{'chronicles':SOC},'private_root_material':'never copy'}):
   self.assertEqual(provision.central_credential('enable',None,{},'vault','compartment'),SOC)

 def test_disable_requires_no_secret_read(self):
  self.assertIsNone(provision.central_credential('disable',None,{},'vault','compartment'))

 def test_admin_grant_is_explicit_exact_and_private(self):
  owner='shadowops:staging:11111111-1111-4111-8111-111111111111'
  requested={'CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE':owner}
  self.assertEqual(provision.central_admin_profile('enable', requested, None, {}, '', ''),owner)
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)
   values={**BASE,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC,'ADMIN_USERNAMES':owner}
   host.write_runtime(host.parse_bundle(''.join(k+'='+v+'\\n' for k,v in values.items())),path,host.STAGING)
   env=(path/'api.env').read_text()
   self.assertIn("ADMIN_USERNAMES='"+owner+"'",env)
   self.assertNotIn(owner,(path/'tunnel.env').read_text())
   self.assertEqual((path/'api.env').stat().st_mode&0o777,0o600)
   self.assertEqual(host.API_ENV_OPTIONAL_KEYS & {'ADMIN_USERNAMES'}, {'ADMIN_USERNAMES'})
   self.assertIn('ADMIN_USERNAMES',provision.render_bundle(values).decode())

 def test_invalid_admin_grants_never_write_runtime_config(self):
  valid='shadowops:staging:11111111-1111-4111-8111-111111111111'
  invalid=['*','evilsysadmin','shadowops:production:'+valid.split(':')[-1],
           'shadowops:staging:22222222-2222-2222-8222-222222222222',
           'shadowops:staging:22222222-2222-4222-7222-222222222222',
           valid+',alice',valid+'\\nADMIN_USERNAMES=*',valid.upper(),'']
  for item in invalid:
   with self.subTest(item=item):
    with self.assertRaises(provision.ProvisionError):
     provision.central_admin_profile('enable', {'CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE':item},None,{},'', '')
    with tempfile.TemporaryDirectory() as temp:
     path=Path(temp)
     with self.assertRaises(host.ReleaseError):
      host.write_runtime({**BASE,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC,'ADMIN_USERNAMES':item},path,host.STAGING)
     self.assertFalse((path/'api.env').exists())
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)
   with self.assertRaises(host.ReleaseError):
    host.write_runtime({**BASE,'ADMIN_USERNAMES':valid},path,host.STAGING)
   self.assertFalse((path/'api.env').exists())
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)
   with self.assertRaises(host.ReleaseError):
    host.write_runtime({**BASE,'ADMIN_USERNAMES':valid,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC},path,host.TARGETS['production'])
   self.assertFalse((path/'api.env').exists())

 def test_admin_grant_persists_or_revokes_without_guessing_legacy_owner(self):
  owner='shadowops:staging:11111111-1111-4111-8111-111111111111'
  with patch.object(provision,'existing_chronicles_bundle',return_value={
      **BASE,'ADMIN_USERNAMES':owner,'SHADOWOPS_IDENTITY_SERVICE_CREDENTIAL':SOC}):
   self.assertEqual(provision.central_admin_profile('preserve',{},None,{},'vault','compartment'),owner)
  self.assertIsNone(provision.central_admin_profile('disable',{},None,{},'vault','compartment'))
  with patch.object(provision,'existing_chronicles_bundle',return_value=BASE):
   self.assertIsNone(provision.central_admin_profile('preserve',{},None,{},'vault','compartment'))
  with patch.object(provision,'existing_chronicles_bundle',return_value={**BASE,'ADMIN_USERNAMES':'*'}):
   with self.assertRaises(provision.ProvisionError):
    provision.central_admin_profile('preserve',{},None,{},'vault','compartment')

 def test_enable_admin_request_is_validated_before_cloud_mutations(self):
  for change in ({'CHRONICLES_CENTRAL_ADMIN':'enable'},
                 {'CHRONICLES_CENTRAL_ADMIN':'enable','CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE':'evilsysadmin'},
                 {'CHRONICLES_CENTRAL_ADMIN':'enable','CHRONICLES_CENTRAL_IDENTITY':'disable',
                  'CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE':'shadowops:staging:11111111-1111-4111-8111-111111111111'}):
   with self.subTest(change=sorted(change)),self.assertRaises(provision.ProvisionError):
    provision.provision(change,None,None)

 def test_cross_environment_enable_is_denied_before_cloud_mutation(self):
  with patch.object(provision,'ENVIRONMENT','production'),self.assertRaises(provision.ProvisionError):
   provision.provision({'CHRONICLES_CENTRAL_IDENTITY':'enable'},None,None)

 def test_unreadable_preserved_state_never_silently_disables_consumer(self):
  with self.assertRaises(provision.ProvisionError):
   provision.central_credential('preserve',None,{},'vault','compartment')


if __name__=='__main__':unittest.main()
