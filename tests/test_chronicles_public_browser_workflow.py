"""Pages must pass real browser login and safe-update UI before release receipt."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / ".github/workflows/chronicles-pages-release.yml"


class PublicBrowserWorkflow(unittest.TestCase):
    def test_browsers_are_live_public_and_after_http_smokes(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        steps = jobs["release"]["steps"]
        names = [s.get("name", "") for s in steps]
        browser = "Real public browser smoke (desktop, mobile, login, update deferral)"
        self.assertLess(names.index("Prove the public update manifest serves the exact SHA"),
                        names.index(browser))
        self.assertLess(names.index(browser),
                        names.index("Record the verified Chronicles Pages source generation"))
        action = next(s for s in steps if s.get("name") == browser)
        self.assertIn("smoke/public-staging.mjs", action["run"])
        self.assertIn("smoke/public-staging-journey.mjs", action["run"])
        self.assertLess(action["run"].index("smoke/public-staging.mjs"),
                        action["run"].index("smoke/public-staging-journey.mjs"))
        self.assertIn("chronicles-journey-*.png", PATH.read_text())
        self.assertIn("playwright install --with-deps chromium", action["run"])
        self.assertEqual(action["env"]["CHRONICLES_SOURCE_SHA"],
                         "${{ steps.source.outputs.sha }}")
        self.assertEqual(action["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertEqual(jobs["release"]["environment"]["name"], "staging")
        self.assertIn("if: always()", PATH.read_text())
        self.assertNotIn("environment=production", action["run"])


if __name__ == "__main__":
    unittest.main()
