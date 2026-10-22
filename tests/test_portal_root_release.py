import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
path=pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_root_release.py"
spec=importlib.util.spec_from_file_location("portal_root_release",path)
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
class Fake:
  account="a"*32
  def __init__(self,dns=None,project=False,domain=False):
    self.dns=dns or []
    self.project=project;self.domain=domain;self.calls=[]
  def request(self,op,path,data=None):
    self.calls.append((op,path,data))
    if path.startswith("/zones?"):
      return 200,[{"name":r.root.ZONE,"id":"z"*32}]
    if "/dns_records?" in path:return 200,self.dns
    if path.endswith("/dns_records") and op=="POST":
      self.dns=[data];return 201,{"id":"record"}
    if path.endswith("/pages/projects") and op=="POST":
      self.project=True;return 201,{"name":r.root.PROJECT,"production_branch":"main"}
    if path.endswith("/pages/projects/"+r.root.PROJECT):
      return (200,{"name":r.root.PROJECT,"production_branch":"main"}) if self.project else (404,None)
    if "/domains/" in path:
      return (200,{"name":r.root.ROOT,"status":"active"}) if self.domain else (404,None)
    if path.endswith("/domains") and op=="POST":
      self.domain=True;return 201,{"name":r.root.ROOT,"status":"pending"}
    raise AssertionError(str((op,path,data)))
class ProductionTests(unittest.TestCase):
  def test_always_refuse_foreign_apex_before_writes(self):
    for row in [
      {"name":r.root.ROOT,"type":"A","content":"192.0.2.7"},
      {"name":r.root.ROOT,"type":"CNAME","content":"foreign.pages.dev","proxied":True},
    ]:
      client=Fake(dns=[row])
      for call in (r.ensure_project,r.ensure_domain):
        with self.assertRaisesRegex(r.Admit,"Foreign"):call(client)
      self.assertTrue(all(op=="GET" for op,*_ in client.calls))
  def test_only_own_project_and_root_cname_created(self):
    cf=Fake()
    r.ensure_project(cf);r.ensure_domain(cf)
    self.assertEqual(len([1 for op,*_ in cf.calls if op=="POST"]),3)
    self.assertEqual(cf.dns[0]["type"],"CNAME")
    self.assertEqual(cf.dns[0]["content"],r.root.TARGET)
    r.ensure_project(cf);r.ensure_domain(cf)
    self.assertEqual(len([1 for op,*_ in cf.calls if op=="POST"]),3)
  def test_never_promote_unverified_local_dist(self):
    with tempfile.TemporaryDirectory() as tmp:
      with self.assertRaises(r.Admit):r.prepare_promotion(tmp,"main")
      with self.assertRaises(r.Admit):r.prepare_promotion(tmp,"a"*40)
  def test_promote_exact_six_glb_sources_without_mutating_asset_bytes(self):
    with tempfile.TemporaryDirectory() as tmp:
      d=pathlib.Path(tmp);(d/"art").mkdir()
      (d/"index.html").write_text("<title>ShadowOps Universe</title>")
      files={}
      for kind in sorted(r.assemble.__globals__["EXPECTED"]):
        blob=b"glTF"+(2).to_bytes(4,"little")+b"contents"*16+kind.encode()
        h=hashlib.sha256(blob).hexdigest()
        p=d/"art"/f"{kind}-{h[:12]}.glb";p.write_bytes(blob)
        files[p.name]=h
      staged=r.assemble(d,"a"*40)
      (d/"release.json").write_text(json.dumps(staged))
      r.prepare_promotion(d,"a"*40)
      promoted=json.loads((d/"release.json").read_text())
      self.assertEqual(promoted["environment"],"production")
      self.assertEqual(promoted["glb_assets"],staged["glb_assets"])
      self.assertEqual({x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (d/"art").glob("*.glb")},files)
  def test_root_https_sha_and_glb_checks(self):
    sha="a"*40
    from unittest.mock import patch
    assets={}
    response={
      "/":("text/html",b'<title>ShadowOps Universe</title><div id="app"></div><script src="/assets/index-abc.js"></script>'),
      "/assets/index-abc.js":("application/javascript",b"var frontend=true;"*25),
    }
    for i,kind in enumerate(sorted(r.assemble.__globals__["EXPECTED"])):
      data=b"glTF"+(2).to_bytes(4,"little")+b"model"*20+bytes([i])
      digest=hashlib.sha256(data).hexdigest();name=f"/art/{kind}-{digest[:12]}.glb"
      assets[name]=digest;response[name]=("model/gltf-binary",data)
    response["/release.json"]=("application/json",json.dumps({"environment":"production","build":sha,"glb_assets":assets}).encode())
    with patch.object(r.staging,"read_https",side_effect=lambda path:response[path]):
      r.verify(sha)
    response["/release.json"]=("application/json",json.dumps({"environment":"staging","build":sha,"glb_assets":assets}).encode())
    with patch.object(r.staging,"read_https",side_effect=lambda path:response[path]):
      with self.assertRaisesRegex(r.Admit,"production SHA"):r.verify(sha)
if __name__=="__main__":unittest.main()
