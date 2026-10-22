import importlib.util
import pathlib
import unittest
P=pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_root_inventory.py"
spec=importlib.util.spec_from_file_location("portal_root_inventory",P)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class Fake:
  account="a"*32
  def __init__(self,dns=None,project=False,domain=False):
    self.dns=dns or []
    self.project=project
    self.domain=domain
    self.calls=[]
  def request(self,method,path,data=None):
    self.calls.append((method,path,data))
    if path.startswith("/zones?"):return 200,[{"name":m.ZONE,"id":"z"*32}]
    if "/dns_records?" in path:return 200,self.dns
    if path.endswith("/pages/projects/"+m.PROJECT):
      return (200,{"name":m.PROJECT,"production_branch":"main"}) if self.project else (404,None)
    if "/domains/" in path:
      return (200,{"name":m.ROOT,"status":"active"}) if self.domain else (404,None)
    raise AssertionError(path)
class InventoryTests(unittest.TestCase):
  def test_empty_root_has_no_owner(self):
    f=Fake()
    self.assertEqual(m.inspect(f),{"apex_dns":"absent","pages_project":"absent","pages_domain":"absent"})
    self.assertTrue(all(op=="GET" for op,*_ in f.calls))
  def test_refuse_to_assume_foreign_apex_is_ours(self):
    for records,status in [
      ([{"name":m.ROOT,"type":"A","content":"192.0.2.7"}],"foreign"),
      ([{"name":m.ROOT,"type":"CNAME","content":"other.pages.dev","proxied":True}],"foreign"),
      ([{"name":m.ROOT,"type":"CNAME","content":m.TARGET,"proxied":False}],"foreign"),
      ([{"name":m.ROOT,"type":"A"},{"name":m.ROOT,"type":"AAAA"}],"ambiguous"),
    ]:
      f=Fake(dns=records)
      self.assertEqual(m.inspect(f)["apex_dns"],status)
      self.assertTrue(all(op=="GET" for op,*_ in f.calls))
  def test_do_not_confuse_mail_records_with_web_dns(self):
    f=Fake(dns=[{"name":m.ROOT,"type":"MX","content":"mail.example"}])
    self.assertEqual(m.inspect(f)["apex_dns"],"absent")
  def test_recognize_production_resources_only_if_exact(self):
    f=Fake(dns=[{"name":m.ROOT,"type":"CNAME","content":m.TARGET,"proxied":True}],
           project=True,domain=True)
    self.assertEqual(m.inspect(f),{"apex_dns":"owned","pages_project":"owned","pages_domain":"owned"})
if __name__=="__main__":unittest.main()
