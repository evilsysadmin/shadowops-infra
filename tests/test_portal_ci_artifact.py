import importlib.util
import pathlib
import unittest
p=pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_ci_artifact.py"
spec=importlib.util.spec_from_file_location("portal_ci_artifact",p)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
run={"id":m.CI_RUN,"head_sha":m.CI_HEAD,"event":"pull_request","status":"completed","conclusion":"success"}
artifact={"name":"portal-compiled-art","expired":False,"size_in_bytes":879225}
class CIArtifact(unittest.TestCase):
  def test_only_matching_tested_art_is_reused(self):
    self.assertTrue(m.eligible(m.PORTAL_TREE,run,[artifact]))
    self.assertFalse(m.eligible("0"*40,run,[artifact]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,{**run,"conclusion":"failure"},[artifact]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,{**run,"head_sha":"1"*40},[artifact]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,run,[{**artifact,"expired":True}]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,run,[{**artifact,"name":"foreign-art"}]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,run,[]))
    self.assertFalse(m.eligible(m.PORTAL_TREE,run,[{**artifact,"size_in_bytes":1}]))
if __name__=="__main__":unittest.main()
