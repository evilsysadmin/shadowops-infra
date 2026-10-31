import base64
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import cka_account_provision as provision
import cka_account_release as release
import identity_staging_provision as idp
from cka_account_contract import AccountError, SECRET, HOST
from test_cka_account_contract import KEYS,BUNDLE

class Cloudflare:
    account='synthetic-account'
    def __init__(self,*,foreign=False,existing=True):self.calls=[];self.foreign=foreign;self.existing=existing
    def call(self,method,path,payload=None):
        self.calls.append((method,path,payload))
        tunnel={'id':'11111111-1111-4111-8111-111111111111','name':provision.NAME,'config_src':'cloudflare'}
        if method=='GET' and 'cfd_tunnel?' in path:return [tunnel] if self.existing else []
        if path.startswith('/zones?'):return [{'id':'synthetic-zone'}]
        if method=='GET' and '/dns_records?' in path:return [{'type':'CNAME','content':'foreign.pages.dev','proxied':True}] if self.foreign else []
        if method=='POST' and path.endswith('/cfd_tunnel'):return tunnel
        if path.endswith('/token'):return BUNDLE['tunnel_token']
        if method in {'PUT','POST'}:return {}
        raise AssertionError(path)

class ProvisionTests(unittest.TestCase):
    def runtime(self,cf,*,identity=None,secret_state=None,keys=KEYS):
        writes=[]
        def model(**kwargs):return NS(**kwargs)
        ops=NS(update_secret_and_wait_for_state=lambda *a,**k:writes.append(('update',a,k)),
               create_secret_and_wait_for_state=lambda value,**k:writes.append(('create',value,k)))
        sdk=NS(vault=NS(VaultsClient=lambda _:NS(list_secrets=object()),VaultsClientCompositeOperations=lambda _:ops,
                       models=NS(Base64SecretContentDetails=model,UpdateSecretDetails=model,CreateSecretDetails=model)),
               pagination=NS(list_call_get_all_results=lambda *a,**k:NS(data=[] if secret_state is None else [NS(id='synthetic-secret',lifecycle_state=secret_state)])))
        custody=identity if identity is not None else {'consumers':{'chronicles':'soc1_'+'B'*43,'cka-simulator':BUNDLE['service_credential']},'ca_certificate_pem':BUNDLE['identity_ca_pem'],'signing_seed':'never-copy-signing-key','mongo_root_password':'never-copy-database-root'}
        with patch.object(provision,'config_from_env',return_value={}),patch.object(provision,'resolve_existing_host',return_value=('compartment','instance')),patch.object(provision,'resolve_vault',return_value=('vault','key',None)),patch.object(provision,'load_existing',return_value=custody):
            value=provision.provision(sdk,{},cf,keys_reader=lambda:keys)
        return value,writes

    def test_independent_bundle_copies_only_cka_service_proof_and_public_keys(self):
        cf=Cloudflare();marker,writes=self.runtime(cf)
        self.assertIn('custody=independent',marker);self.assertEqual(len(writes),1)
        details=writes[0][1];self.assertEqual(details.secret_name,SECRET)
        actual=json.loads(base64.b64decode(details.secret_content.content))
        self.assertEqual(actual,BUNDLE)
        encoded=json.dumps(actual)
        self.assertNotIn('never-copy',encoded);self.assertNotIn('chronicles',encoded)
        self.assertTrue(all('chess-studio' not in path and 'chronicles' not in path for _,path,_ in cf.calls))
        self.assertTrue(any(method=='PUT' and payload==provision.desired_ingress() for method,_,payload in cf.calls))

    def test_foreign_dns_denies_before_any_mutation_even_without_existing_tunnel(self):
        for existing in [True,False]:
            cf=Cloudflare(foreign=True,existing=existing)
            with self.assertRaises(provision.ProvisionError):self.runtime(cf)
            self.assertTrue(all(method=='GET' for method,_,_ in cf.calls))

    def test_missing_consumer_or_private_key_in_public_jwks_deny_before_cf_mutation(self):
        for edits in [{'identity':{'consumers':{'chronicles':'old'}}},{'keys':{'keys':[{**KEYS['keys'][0],'d':'private'}]}}]:
            cf=Cloudflare()
            with self.assertRaises((AccountError,provision.ProvisionError)):self.runtime(cf,**edits)
            self.assertEqual(cf.calls,[])

    def test_pending_secret_is_not_permission_to_replace_custody(self):
        cf=Cloudflare(existing=False)
        with self.assertRaises(provision.ProvisionError):self.runtime(cf,secret_state='PENDING_DELETION')
        self.assertTrue(all(method=='GET' for method,_,_ in cf.calls))

    def test_identity_activation_requires_installed_cka_policy_before_cf_or_custody_mutation(self):
        cf=Cloudflare()
        with patch.object(idp,'config_from_env',return_value={}),patch.object(idp,'resolve_existing_host',return_value=('c','i')),patch.object(idp,'resolve_vault',return_value=('v','k',None)),patch.object(release,'execute',side_effect=AccountError('policy absent')):
            with self.assertRaises(AccountError):idp.provision(NS(),{'IDENTITY_STAGING_CKA':'enable'},cf)
        self.assertEqual(cf.calls,[])

if __name__=='__main__':unittest.main()
