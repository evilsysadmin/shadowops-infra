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

 def test_cross_environment_enable_is_denied_before_cloud_mutation(self):
  with patch.object(provision,'ENVIRONMENT','production'),self.assertRaises(provision.ProvisionError):
   provision.provision({'CHRONICLES_CENTRAL_IDENTITY':'enable'},None,None)

 def test_unreadable_preserved_state_never_silently_disables_consumer(self):
  with self.assertRaises(provision.ProvisionError):
   provision.central_credential('preserve',None,{},'vault','compartment')


if __name__=='__main__':unittest.main()
