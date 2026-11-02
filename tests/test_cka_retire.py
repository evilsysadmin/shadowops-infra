import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import cka_retire_cloud as cloud
import cka_retire_host as host
from identity_staging_bundle import generate,enable_cka

class Cloudflare:
    account='a'*32
    def __init__(self):
        self.writes=[];self.deleted=set();self.foreign=None;self.connected=False
        self.tunnels=[{'name':name,'id':f'00000000-0000-4000-8000-00000000000{index}','config_src':'cloudflare'} for index,name in enumerate(cloud.TUNNELS)]
    def call(self,method,path,data=None):
        if method!='GET':
            self.writes.append((method,path,data))
            if method=='DELETE':self.deleted.add(path)
            return {}
        if path.startswith('/zones?'):return [{'id':'b'*32,'name':cloud.ZONE}]
        if '/dns_records?' in path:
            from urllib.parse import parse_qs,urlsplit
            name=parse_qs(urlsplit(path).query)['name'][0]
            target=next((key+'.pages.dev' for key,value in cloud.PAGES.items() if value==name),None)
            if target is None:target=next(t['id']+'.cfargotunnel.com' for t in self.tunnels if cloud.TUNNELS[t['name']][0]==name)
            identity=str(list(cloud.PAGES.values()).index(name)+1) if name in cloud.PAGES.values() else str(list(v[0] for v in cloud.TUNNELS.values()).index(name)+5)
            identity=identity*32
            if f'/zones/{"b"*32}/dns_records/{identity}' in self.deleted:return []
            return [{'id':identity,'name':name,'type':'CNAME','content':'foreign.pages.dev' if self.foreign=='dns' else target}]
        if '/pages/projects?' in path:return [{'name':n} for n in cloud.PAGES if f'/accounts/{self.account}/pages/projects/{n}' not in self.deleted]
        if '/pages/projects/' in path:
            name=path.rsplit('/',1)[1]
            return {'name':name,'subdomain':name+'.pages.dev','domains':[cloud.PAGES[name]]+(['other.shadowops.dpdns.org'] if self.foreign=='page' else [])}
        if '/cfd_tunnel?' in path:return [t for t in self.tunnels if f'/accounts/{self.account}/cfd_tunnel/{t["id"]}' not in self.deleted]
        if path.endswith('/configurations'):
            tunnel=next(t for t in self.tunnels if t['id'] in path)
            hostname,service=cloud.TUNNELS[tunnel['name']]
            return {'config':{'ingress':[{'hostname':hostname,'service':'ssh://shared-host:22' if self.foreign=='ingress' else service},{'service':'http_status:404'}]}}
        if path.endswith('/connections'):return [{'id':'live'}] if self.connected else []
        raise AssertionError(path)

class Retirement(unittest.TestCase):
    def test_exact_cloud_inventory_delete_and_rerun(self):
        cf=Cloudflare();plan=cloud.cloud_plan(cf)
        self.assertEqual((len(plan['dns']),len(plan['projects']),len(plan['tunnels'])),(4,2,2))
        self.assertEqual(cf.writes,[])
        cloud.retire_cloud(cf,plan)
        after=cloud.cloud_plan(cf)
        self.assertFalse(any(after[k] for k in ['dns','projects','tunnels']))
        for method,path,data in cf.writes:
            self.assertNotIn('identity-staging',path)
            self.assertNotIn('chess',path)
        writes=len(cf.writes);cloud.retire_cloud(cf,after);self.assertEqual(writes,len(cf.writes))
    def test_foreign_resources_fail_before_any_write(self):
        for foreign in ['dns','page','ingress']:
            cf=Cloudflare();cf.foreign=foreign
            with self.assertRaises(cloud.ProvisionError):cloud.cloud_plan(cf)
            self.assertEqual(cf.writes,[])
    def test_active_connector_blocks_tunnel_delete_after_withdrawal(self):
        cf=Cloudflare();cf.connected=True
        with self.assertRaises(cloud.ProvisionError):cloud.retire_cloud(cf,cloud.cloud_plan(cf))
        self.assertFalse(any(m=='DELETE' and '/cfd_tunnel/' in p for m,p,_ in cf.writes))
    def test_cka_consumer_removal_preserves_every_other_key_and_credential(self):
        original=enable_cka(generate('synthetic-tunnel-token-'+'a'*60))
        before=copy.deepcopy(original);after=cloud.remove_consumer(original)
        self.assertEqual(before,original)
        self.assertNotIn('cka-simulator',after['consumers'])
        self.assertEqual(after['consumers']['chronicles'],original['consumers']['chronicles'])
        for key in set(original)-{'consumers'}:self.assertEqual(original[key],after[key])
        self.assertEqual(after,cloud.remove_consumer(after))
    def test_host_scope_rejects_shared_project_image_or_mount(self):
        value={'Name':'/own','Config':{'Image':'ghcr.io/evilsysadmin/cka-account-staging@sha256:'+'a'*64,
            'Labels':{'com.docker.compose.project':'shadowops-cka-account-staging','com.docker.compose.service':'cka-account'}},'Mounts':[]}
        host.validate_container(value)
        for kind in ['project','image','mount']:
            changed=copy.deepcopy(value)
            if kind=='project':changed['Config']['Labels']['com.docker.compose.project']='shadowops-identity-staging'
            if kind=='image':changed['Config']['Image']='foreign:image'
            if kind=='mount':changed['Mounts']=[{'Type':'bind','Source':'/var/run/docker.sock'}]
            with self.assertRaises(host.RetireError):host.validate_container(changed)
    def test_retired_workflows_cannot_publish_and_identity_cannot_enable_cka(self):
        for path in (ROOT/'.github/workflows').glob('cka-*.yml'):
            if path.name=='cka-retire.yml':continue
            text=path.read_text()
            self.assertIn('false',text,path.name)
            self.assertIn('CKA online retired',text,path.name)
        source=(ROOT/'.github/workflows/identity-staging-operations.yml').read_text()
        self.assertNotIn('options: [preserve, enable]',source)
        import identity_staging_provision as identity
        with self.assertRaises(cloud.ProvisionError):identity.provision(NS(),{'IDENTITY_STAGING_CKA':'enable'},NS())
    def test_legacy_bootstrap_cannot_reach_ssh(self):
        for action in ['bootstrap','cluster-bootstrap','api-start','tunnel-start']:
            result=subprocess.run(['bash',str(ROOT/'host/bootstrap-cka-lab-over-ssh.sh'),action],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('retired',result.stderr)
    def test_operator_script_is_fixed_protected_source_and_shell_valid(self):
        path=ROOT/'host/cka-retire-over-ssh.sh'
        self.assertEqual(subprocess.run(['bash','-n',str(path)]).returncode,0)
        text=path.read_text();self.assertIn('refs/heads/main',text);self.assertIn('StrictHostKeyChecking=ask',text)
        self.assertIn('scripts/cka_retire_host.py "$action"',text)

if __name__=='__main__':unittest.main()
