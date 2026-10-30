from __future__ import annotations
import copy
import importlib.util
import json
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import identity_staging_bundle as bundle
import identity_staging_provision as provision
spec=importlib.util.spec_from_file_location('identity_host',ROOT/'host/identity-staging-deploy.py')
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class BundleTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.value=bundle.generate('synthetic-tunnel-'+'a'*64)

 def test_real_certificate_trust_and_pinned_host(self):
  with tempfile.TemporaryDirectory() as temp:
   directory=Path(temp)
   for name,key in [('ca.pem','ca_certificate_pem'),('leaf.pem','tls_certificate_pem'),('key.pem','tls_private_key_pem')]:
    (directory/name).write_text(self.value[key])
   context=ssl.create_default_context(cafile=str(directory/'ca.pem'))
   context.load_cert_chain(str(directory/'leaf.pem'),str(directory/'key.pem'))
   valid=subprocess.run(['openssl','verify','-CAfile',str(directory/'ca.pem'),'-verify_hostname',bundle.HOST,str(directory/'leaf.pem')],capture_output=True)
   self.assertEqual(valid.returncode,0)
   wrong=subprocess.run(['openssl','verify','-CAfile',str(directory/'ca.pem'),'-verify_hostname','id.shadowops.dpdns.org',str(directory/'leaf.pem')],capture_output=True)
   self.assertNotEqual(wrong.returncode,0)

 def test_service_receives_only_application_credentials(self):
  config=bundle.service_config(self.value)
  self.assertEqual(config['environment'],'staging')
  self.assertEqual(set(config['consumers']),{'chronicles'})
  encoded=json.dumps(config)
  for key in ['ca_private_key_pem','mongo_root_password','mongo_replica_key','backup_key','tunnel_token']:
   self.assertNotIn(self.value[key],encoded)
  self.assertNotEqual(self.value['signing_seed'],self.value['consumers']['chronicles'][5:])
  self.assertIn('@identity-mongo:27017/shadowops_identity_staging?',config['mongo_uri'])

 def test_wrong_environment_unknown_fields_and_unsafe_credentials_rejected(self):
  for key,value in [('environment','production'),('schema',True),('surprise','x'),('tunnel_token',"unsafe\nvalue"),('consumers',{'cka-simulator':'soc1_'+'x'*43}),('mongo_root_password',self.value['mongo_application_password'])]:
   with self.subTest(key=key):
    config=copy.deepcopy(self.value);config[key]=value
    with self.assertRaises(bundle.BundleError):bundle.validate(config)

 def test_release_arguments_cannot_select_shell_or_production(self):
  args=['deploy','sha256:'+'a'*64,'b'*40,'ocid1.vault.oc1.eu.exampleidentifier']
  host.request(*args)
  for index,value in [(0,'production'),(1,'latest'),(1,'sha256:'+'a'*64+';echo injected'),(2,'main'),(3,'$(env)')]:
   changed=args.copy();changed[index]=value
   with self.assertRaises(host.DeployError):host.request(*changed)

 def test_stopped_containers_and_published_ports_cannot_be_adopted(self):
  labels={'com.docker.compose.project':host.PROJECT,'com.docker.compose.service':'identity'}
  valid={'Labels':labels,'Bindings':{}}
  host.assert_existing_identity_containers([valid])
  for rows in [[valid,valid],[{'Labels':labels,'Bindings':{'9443/tcp':[{'HostIp':'0.0.0.0','HostPort':'9443'}]}}],[{'Labels':dict(labels,**{'com.docker.compose.service':'unexpected'}),'Bindings':{}}]]:
   with self.assertRaises(host.DeployError):host.assert_existing_identity_containers(rows)

class ProvisionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.original=bundle.generate('synthetic-token-'+'a'*64)

 def test_retry_preserves_private_material_and_updates_rotated_tunnel_token(self):
  for token,expected_writes in [(self.original['tunnel_token'],0),('replacement-token-'+'b'*64,1)]:
   with self.subTest(rotated=bool(expected_writes)):
    cf=SimpleNamespace(account='fixture',call=lambda method,path,*args:token)
    with patch.object(provision,'config_from_env',return_value={}),patch.object(provision,'resolve_existing_host',return_value=('compartment','instance')),patch.object(provision,'resolve_vault',return_value=('vault','key','compartment')),patch.object(provision,'load_existing',return_value=copy.deepcopy(self.original)),patch.object(provision,'ensure_tunnel',return_value='fixture'),patch.object(provision,'dns_plan',return_value=('zone','target',True)),patch.object(provision,'store') as store,patch.object(provision,'generate') as generate:
     provision.provision(SimpleNamespace(),{},cf)
     generate.assert_not_called()
     self.assertEqual(store.call_count,expected_writes)
     if expected_writes:
      updated=store.call_args.args[-1]
      self.assertEqual(updated['tunnel_token'],token)
      for key in bundle.KEYS-{'tunnel_token'}:self.assertEqual(updated[key],self.original[key])

 def test_dns_conflict_stops_before_configuration_or_vault_mutation(self):
  calls=[]
  cf=SimpleNamespace(account='fixture',call=lambda method,path,*args:calls.append(method) or ([{'id':'zone'}] if path.startswith('/zones?') else [{'type':'CNAME','content':'foreign','proxied':True}]))
  with self.assertRaises(provision.ProvisionError):provision.dns_plan(cf,'fixture')
  self.assertEqual(calls,['GET','GET'])

 def test_origin_authenticates_private_tls_and_has_deny_default(self):
  ingress=provision.desired_ingress()['config']['ingress']
  self.assertEqual(ingress[-1],{'service':'http_status:404'})
  self.assertEqual(ingress[0]['hostname'],bundle.HOST)
  self.assertEqual(ingress[0]['service'],'https://identity:9443')
  self.assertFalse(ingress[0]['originRequest']['noTLSVerify'])
  self.assertEqual(ingress[0]['originRequest']['originServerName'],bundle.HOST)

 def test_existing_custody_read_error_never_becomes_new_keys(self):
  class ServiceError(Exception):pass
  sdk=SimpleNamespace(pagination=SimpleNamespace(list_call_get_all_results=lambda *a,**k:SimpleNamespace(data=[SimpleNamespace(lifecycle_state='ACTIVE')])),vault=SimpleNamespace(VaultsClient=lambda config:SimpleNamespace(list_secrets=None)),secrets=SimpleNamespace(SecretsClient=lambda config:SimpleNamespace(get_secret_bundle_by_name=lambda **k:(_ for _ in ()).throw(ServiceError()))),exceptions=SimpleNamespace(ServiceError=ServiceError))
  with self.assertRaises(provision.ProvisionError):provision.load_existing(sdk,{},'vault','compartment')


if __name__=='__main__':unittest.main()
