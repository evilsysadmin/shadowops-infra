import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "portal_pages", pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_pages.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)

class FakeCloudflare:
    account="a"*32
    def __init__(self, foreign=False, dup=False, created=False, domain=False, dns=False):
        self.foreign,self.dup,self.created,self.domain,self.dns=foreign,dup,created,domain,dns
        self.calls=[]
    def request(self,method,path,data=None):
        self.calls.append((method,path,data))
        if path.startswith("/zones?"):
            return 200,[{"id":"z"*32,"name":p.ZONE}]
        if "/dns_records?" in path:
            rows=[{"name":p.HOST,"type":"CNAME","content":"foreign.pages.dev" if self.foreign else p.TARGET,"proxied":True}] if self.dns or self.foreign else []
            return 200,rows*2 if self.dup else rows
        if path.endswith("/dns_records") and method=="POST":
            assert data["name"]==p.HOST and data["content"]==p.TARGET
            self.dns=True
            return 200,{"id":"record"}
        if path.endswith("/pages/projects") and method=="POST":
            assert data=={"name":p.PROJECT,"production_branch":"main"}
            self.created=True
            return 200,{"name":p.PROJECT,"production_branch":"main"}
        if path.endswith("/pages/projects/"+p.PROJECT):
            return (200,{"name":p.PROJECT,"production_branch":"main"}) if self.created else (404,None)
        if path.endswith("/domains/"+p.HOST):
            return (200,{"name":p.HOST,"status":"active"}) if self.domain else (404,None)
        if path.endswith("/domains") and method=="POST":
            assert data=={"name":p.HOST}
            self.domain=True
            return 200,{"name":p.HOST,"status":"pending"}
        raise AssertionError(f"Unexpected {method} {path}")

class PortalOwnerTests(unittest.TestCase):
    def test_constants_are_staging_only(self):
        self.assertEqual(p.HOST,"staging.shadowops.dpdns.org")
        self.assertEqual(p.PROJECT,"shadowops-universe-staging")
        self.assertNotEqual(p.HOST,p.ZONE)
    def test_inspect_is_read_only(self):
        cf=FakeCloudflare()
        _,status=p.inspect(cf)
        self.assertEqual(status,{"project":"absent","domain":"absent","dns":"absent"})
        self.assertTrue(all(op=="GET" for op,*_ in cf.calls))
    def test_foreign_owner_and_duplicate_abort_without_mutations(self):
        for cf in (FakeCloudflare(foreign=True),FakeCloudflare(dup=True,dns=True)):
            with self.assertRaises(p.AdmissionError):p.project(cf)
            with self.assertRaises(p.AdmissionError):p.domain(cf)
            self.assertTrue(all(op=="GET" for op,*_ in cf.calls))
    def test_only_dedicated_project_and_staging_record_are_written(self):
        cf=FakeCloudflare()
        p.project(cf)
        p.domain(cf)
        self.assertTrue(cf.created and cf.domain and cf.dns)
        writes=[(url,data) for op,url,data in cf.calls if op=="POST"]
        self.assertEqual(len(writes),3)
        self.assertTrue(all(p.HOST in str(data) or data.get("name")==p.PROJECT for url,data in writes))
        p.project(cf);p.domain(cf)
        self.assertEqual(len([1 for op,*_ in cf.calls if op=="POST"]),3)
    def test_existing_owned_target_is_untouched(self):
        cf=FakeCloudflare(created=True,domain=True,dns=True)
        p.project(cf);p.domain(cf)
        self.assertTrue(all(op=="GET" for op,*_ in cf.calls))
    def test_sha_rejected_before_network(self):
        for s in ("","main","0"*39,"X"*40):
            with self.assertRaisesRegex(p.AdmissionError,"SHA"):p.public_check(s)
    def test_missing_credentials_are_rejected(self):
        with self.assertRaises(p.AdmissionError):p.CloudflareClient({})
    def test_cloudflare_redirects_are_blocked(self):
        self.assertIsNone(p.NoRedirect().redirect_request if False else None)
        with self.assertRaisesRegex(p.AdmissionError,"Redirect"):
            p.NoRedirect().redirect_request(None,None,302,"redirect",{},"https://evil.example")
    def test_live_root_script_manifest_and_all_glbs(self):
        sha="a"*40
        import hashlib
        blobs={name:b"glTF"+(2).to_bytes(4,"little")+b"some-glb"+bytes([i])*90
               for i,name in enumerate(("celestial-vault","gallery-frame","armillary","relic-chess","relic-chronicles","relic-star"),1)}
        art={}
        responses={
          "/":("text/html",b'<title>ShadowOps Universe</title><div id="app"></div><script src="/assets/index-hash.js"></script>'),
          "/assets/index-hash.js":("application/javascript",b"var portal = true; "*30),
        }
        for name,data in blobs.items():
            digest=hashlib.sha256(data).hexdigest()
            url="/art/"+name+"-"+digest[:12]+".glb"
            art[url]=digest
            responses[url]=("model/gltf-binary",data)
        responses["/release.json"]=("application/json",json.dumps({"build":sha,"environment":"staging","glb_assets":art}).encode())
        with patch.object(p,"read_https",side_effect=lambda path:responses[path]):
            p.public_check(sha)
        asset=next(iter(art))
        responses[asset]=("text/html",b"<html>Missing model</html>")
        with patch.object(p,"read_https",side_effect=lambda path:responses[path]):
            with self.assertRaisesRegex(p.AdmissionError,"GLB"):p.public_check(sha)

if __name__=="__main__":unittest.main()
