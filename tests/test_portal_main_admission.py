import importlib.util
import pathlib
import unittest
path=pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_main_admission.py"
spec=importlib.util.spec_from_file_location("portal_main_admission",path)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A="a"*40
B="b"*40
def compare(*paths):
    return {"status":"ahead","total_commits":2,"files":[{"filename":p} for p in paths]}
class Tests(unittest.TestCase):
    def test_exact_is_allowed(self):self.assertEqual(m.check(A,A),"same-sha")
    def test_unrelated_chronicles_is_allowed(self):
        self.assertEqual(m.check(A,B,compare("scripts/chronicles_watch.py",".github/workflows/chronicles-staging-watch.yml")),"unrelated-infra-only")
    def test_relevant_portal_change_is_blocked(self):
        for name in ("portal/src/world.js","scripts/portal_pages.py","scripts/portal_root_release.py",
                     "tests/test_portal_pages.py",".github/workflows/portal-pages-staging.yml",
                     ".github/workflows/portal-root-release.yml",".github/workflows/shadowops-portal-ci.yml"):
            with self.assertRaisesRegex(ValueError,"superseded"):m.check(A,B,compare(name))
    def test_renaming_protected_source_blocks(self):
        info=compare("docs/rename.md")
        info["files"][0]["previous_filename"]="portal/src/world.js"
        with self.assertRaises(ValueError):m.check(A,B,info)
    def test_missing_or_ambiguous_comparison_blocks(self):
        for diff in (None,{"status":"diverged","total_commits":2,"files":[]},
                     {"status":"ahead","total_commits":101,"files":[]},
                     {"status":"ahead","total_commits":1,"files":[{"filename":"docs/x"}]*300}):
            with self.assertRaises(ValueError):m.check(A,B,diff)
if __name__=="__main__":unittest.main()
