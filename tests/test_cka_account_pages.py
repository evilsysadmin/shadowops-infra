import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import cka_account_pages as pages

class PagesTests(unittest.TestCase):
    def test_foreign_dns_and_existing_public_demo_target_are_never_overwritten(self):
        for target in ['foreign.pages.dev','cka-simulator.pages.dev']:
            calls=[]
            def request(method,path,payload=None):
                calls.append((method,path))
                if path.startswith('/zones?'):return 200,[{'name':pages.ZONE,'id':'zone'}]
                if '/dns_records?' in path:return 200,[{'name':pages.HOST,'type':'CNAME','content':target,'proxied':True}]
                raise AssertionError(path)
            with patch.dict(os.environ,{'CLOUDFLARE_ACCOUNT_ID':'account'}),patch.object(pages,'request',side_effect=request):
                with self.assertRaises(RuntimeError):pages.preflight()
            self.assertTrue(all(method=='GET' for method,_ in calls))

    def test_disable_removes_only_owned_domain_and_dns_without_deleting_project(self):
        calls=[]
        identifier='f'*32
        def request(method,path,payload=None):
            calls.append((method,path))
            if path.startswith('/zones?'):return 200,[{'name':pages.ZONE,'id':'zone'}]
            if '/dns_records?' in path:return 200,[{'id':identifier,'name':pages.HOST,'type':'CNAME','content':pages.TARGET,'proxied':True}]
            if method=='GET' and path==pages.project_path():return 200,{'name':pages.PROJECT,'production_branch':'main'}
            if method=='GET' and path==pages.domain_path():return 200,{'name':pages.HOST,'status':'active'}
            if method=='DELETE':return 200,{}
            raise AssertionError((method,path))
        with patch.dict(os.environ,{'CLOUDFLARE_ACCOUNT_ID':'account'}),patch.object(pages,'request',side_effect=request),patch('builtins.print'):
            pages.disable_domain()
        deletes=[path for method,path in calls if method=='DELETE']
        self.assertEqual(len(deletes),2)
        self.assertTrue(any('/domains/staging.cka.' in path for path in deletes))
        self.assertTrue(any(path.endswith('/dns_records/'+identifier) for path in deletes))
        self.assertFalse(any(path.endswith('/pages/projects/cka-account-staging') for path in deletes))

    def test_independent_project_and_exact_source_release_mode(self):
        self.assertEqual(pages.HOST,'staging.cka.shadowops.dpdns.org')
        self.assertEqual(pages.PROJECT,'cka-account-staging')
        sha='a'*40
        class Response:
            status=200
            def __init__(self,body):self.body=body
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def read(self,limit):return self.body[:limit]
        def get(req,**kwargs):
            self.assertTrue(req.full_url.startswith('https://staging.cka.shadowops.dpdns.org/'))
            if req.full_url.endswith('/release.json'):return Response(json.dumps({'application':'cka-exam-simulator','build':sha,'mode':'account-staging-preview'}).encode())
            return Response(b'<title>CKA // LAB</title>')
        with patch.object(pages.urllib.request,'urlopen',side_effect=get),patch('builtins.print'):pages.verify(sha)

if __name__=='__main__':unittest.main()
