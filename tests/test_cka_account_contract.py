import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import cka_account_contract as contract
import cka_account_release as release
import cka_account_verify as verify
import identity_staging_bundle as identity
spec=importlib.util.spec_from_file_location('cka_host',ROOT/'host/cka-account-staging-deploy.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
SHA='a'*40;DIGEST='sha256:'+'b'*64;VAULT='ocid1.vault.oc1.eu.exampleidentifier'
KEYS={'keys':[{'kty':'OKP','crv':'Ed25519','alg':'EdDSA','use':'sig','kid':'synthetic-key','x':base64.urlsafe_b64encode(b'x'*32).decode().rstrip('=')}]}
BUNDLE={'schema':1,'environment':'staging','jwks':KEYS,'identity_ca_pem':'-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----','service_credential':'soc1_'+'A'*43,'tunnel_token':'synthetic-'+'a'*64}

def document():
    common={'platform':'linux/arm64','user':'65532:65532','read_only':True,'init':True,'cap_drop':['ALL'],
            'security_opt':['no-new-privileges:true'],'pids_limit':64,'mem_limit':256*1024*1024,'cpus':0.5}
    return {'networks':{'origin':{'name':'shadowops-cka-account-staging-origin','internal':True},'identity-origin':{'name':'shadowops-identity-staging-origin','external':True},'tunnel-egress':{'name':'shadowops-cka-account-staging-tunnel-egress'}},'services':{
        'cka-account':{**copy.deepcopy(common),'image':contract.IMAGE+DIGEST,'networks':{'origin':None,'identity-origin':None},'volumes':[{'type':'bind','source':str(host.ROOT/'account.json'),'target':'/run/secrets/cka-account-staging.json','read_only':True}]},
        'cka-account-tunnel':{**copy.deepcopy(common),'image':contract.TUNNEL_IMAGE,'networks':{'origin':None,'tunnel-egress':None},'command':['tunnel','--no-autoupdate','--metrics','127.0.0.1:20242','run']}}}

class BundleTests(unittest.TestCase):
    def test_narrow_bundle_and_public_keys_only(self):
        contract.validate(BUNDLE)
        value=contract.account_config(BUNDLE,SHA)
        self.assertEqual(set(value),{'environment','service_credential','jwks','identity_ca_pem','build'})
        self.assertNotIn('tunnel_token',value)
        for edit in [{'environment':'production'},{'mongo_root_password':'forbidden'},{'schema':True},
                     {'service_credential':'soc1_'+'x'*43},{'tunnel_token':'$(env)'},{'jwks':{'keys':[]}}]:
            with self.subTest(edit=tuple(edit)):
                with self.assertRaises(contract.AccountError):contract.validate({**BUNDLE,**edit})
        for edit in [{'d':'private'}, {'kty':'RSA'}, {'x':'bad'}]:
            value=copy.deepcopy(BUNDLE);value['jwks']['keys'][0].update(edit)
            with self.assertRaises(contract.AccountError):contract.validate(value)

    def test_opt_in_preserves_all_previous_custody_and_is_idempotent(self):
        before=identity.generate('synthetic-tunnel-'+'a'*64)
        original=copy.deepcopy(before);after=identity.enable_cka(before)
        self.assertEqual(before,original)
        for key in before:
            if key!='consumers':self.assertEqual(before[key],after[key])
        self.assertEqual(after['consumers']['chronicles'],before['consumers']['chronicles'])
        self.assertNotEqual(after['consumers']['cka-simulator'],after['consumers']['chronicles'])
        self.assertEqual(identity.enable_cka(after),after)
        with self.assertRaises(identity.BundleError):
            identity.validate({**after,'consumers':dict.fromkeys(after['consumers'],after['consumers']['chronicles'])})
        for key in ['signing_seed','backup_key']:
            unsafe=copy.deepcopy(after);unsafe['consumers']['cka-simulator']='soc1_'+after[key].rstrip('=')
            with self.assertRaises(identity.BundleError):identity.validate(unsafe)

class HostTests(unittest.TestCase):
    def test_fixed_compose_boundary_rejects_privilege_ports_mounts_and_overrides(self):
        host.compose_policy(document(),DIGEST)
        normalized=document();normalized['services']['cka-account']['mem_limit']='256m'
        normalized['services']['cka-account-tunnel']['mem_limit']='128m'
        host.compose_policy(normalized,DIGEST)
        changes=[('ports',[{'target':8080,'published':'8080'}]),('privileged',True),('read_only',False),
                 ('user','0:0'),('image','other@'+DIGEST),('cap_add',['SYS_ADMIN']),('network_mode','host'),
                 ('volumes',[]),('entrypoint',['sh']),('command',['sh']),('environment',{'PYTHONPATH':'/other'}),
                 ('networks',{'origin':None,'public-egress':None}),('pids_limit',0),('cpus',8),('mem_limit',0)]
        for key,value in changes:
            changed=document();changed['services']['cka-account'][key]=value
            with self.subTest(key=key):
                with self.assertRaises(contract.AccountError):host.compose_policy(changed,DIGEST)
        extra=document();extra['services']['runner']={}
        with self.assertRaises(contract.AccountError):host.compose_policy(extra,DIGEST)

    def test_identity_network_must_be_internal_and_owned_by_the_actual_idp(self):
        good={'Name':'shadowops-identity-staging-origin','Internal':True,'Labels':{'com.docker.compose.project':'shadowops-identity-staging'}}
        host.verify_identity_network([good])
        for change in [{'Internal':False},{'Name':'other'},{'Labels':{}}]:
            with self.assertRaises(contract.AccountError):host.verify_identity_network([{**good,**change}])

    def test_stopped_or_running_foreign_containers_cannot_be_adopted(self):
        row={'Labels':{'com.docker.compose.project':contract.PROJECT,'com.docker.compose.service':'cka-account'},
             'Bindings':{},'Privileged':False,'NetworkMode':'private','Mounts':[{'Type':'bind','RW':False,'Source':str(host.ROOT/'account.json'),'Destination':'/run/secrets/cka-account-staging.json'}]}
        host.existing_containers([row])
        for changed in [[row,row],[{**row,'Privileged':True}],[{**row,'Bindings':{'8080/tcp':[]}}],
                        [{**row,'Mounts':[]}],[{**row,'NetworkMode':'host'}]]:
            with self.assertRaises(contract.AccountError):host.existing_containers(changed)

    def test_backup_gate_checks_actual_schema_age_size_and_digest(self):
        now=datetime.now(timezone.utc)
        value={'schema':1,'environment':'staging','created_at':now.isoformat(),'encrypted_bytes':1234,'sha256':'c'*64}
        with tempfile.TemporaryDirectory() as temp,patch.object(host,'trusted'):
            path=Path(temp)/'receipt.json';path.write_text(json.dumps(value));host.fresh_backup(now,path=path)
            for edit in [{'created_at':(now-timedelta(hours=27)).isoformat()},{'created_at':(now+timedelta(seconds=2)).isoformat()},
                         {'environment':'production'},{'encrypted_bytes':False},{'sha256':'invalid'}]:
                path.write_text(json.dumps({**value,**edit}))
                with self.assertRaises(contract.AccountError):host.fresh_backup(now,path=path)

class CommandTests(unittest.TestCase):
    def test_only_exact_argument_validated_root_commands(self):
        command=release.command_for('deploy',DIGEST,SHA,VAULT)
        self.assertEqual(command.count('sudo --non-interactive'),1)
        self.assertNotIn('docker ',command);self.assertNotIn('TOKEN',command);self.assertNotIn('SECRET',command)
        self.assertIn(' inspect\n',release.command_for('inspect'))
        self.assertIn(' stop\n',release.command_for('stop'))
        for args in [('restore','','',''),('inspect',DIGEST,SHA,VAULT),('deploy','latest',SHA,VAULT),
                     ('deploy',DIGEST,'main',VAULT),('deploy',DIGEST,SHA,VAULT+';id')]:
            with self.assertRaises(contract.AccountError):release.command_for(*args)

    def test_command_completion_never_substitutes_for_public_source_verification(self):
        self.assertEqual(release.receipt('SUCCEEDED',SimpleNamespace(exit_code=0,text=''),'deploy',DIGEST,SHA),'CKA_ACCOUNT_DEPLOY_COMMAND_COMPLETED')
        for state,code,text in [('FAILED',0,''),('SUCCEEDED',None,''),('SUCCEEDED',1,''),('SUCCEEDED',0,'unexpected private output')]:
            with self.assertRaises(contract.AccountError):release.receipt(state,SimpleNamespace(exit_code=code,text=text),'deploy',DIGEST,SHA)

    def test_public_proof_requires_exact_source_and_absent_privileged_routes(self):
        def response(path):
            if path=='/api/account/release':return 200,json.dumps({'application':'cka-exam-simulator','build':SHA,'mode':'account-only-staging'}).encode()
            if path=='/readyz':return 200,b'{}'
            return (401 if path=='/api/account/me' else 404),b''
        self.assertEqual(verify.verify(SHA,read=response),'CKA_ACCOUNT_PUBLIC_SOURCE_OK '+SHA)
        def wrong(path):return (200,b'{}') if path=='/api/scenarios' else response(path)
        times=iter([0,999])
        with self.assertRaises(contract.AccountError):verify.verify(SHA,read=wrong,clock=lambda:next(times),pause=lambda _:None)

if __name__=='__main__':unittest.main()
