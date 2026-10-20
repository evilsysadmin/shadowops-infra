"""Offline contracts for public browser smoke independent from source main."""
from pathlib import Path
import unittest
import yaml


class BrowserOnlyReleaseTest(unittest.TestCase):
    def test_real_deployed_sha_and_safe_staging_secret(self):
        y = yaml.load((Path(__file__).resolve().parents[1] /
            ".github/workflows/chronicles-public-browser-smoke.yml").read_text(), Loader=yaml.BaseLoader)
        steps = y["jobs"]["browser"]["steps"]
        names = [s.get("name", "") for s in steps]
        self.assertLess(names.index("Read the public SHA actually served by Pages"),
                        names.index("Validate the actual public Chronicles game in desktop and mobile"))
        code = next(s for s in steps if s.get("name") == "Read the public SHA actually served by Pages")["run"]
        self.assertIn("/release.json", code)
        self.assertIn('[[ "$sha" =~ ^[0-9a-f]{40}$ ]]', code)
        browser = next(s for s in steps if s.get("name") == "Validate the actual public Chronicles game in desktop and mobile")
        self.assertIn("smoke/public-staging.mjs", browser["run"])
        self.assertEqual(browser["env"]["CHRONICLES_SOURCE_SHA"], "${{ steps.current.outputs.sha }}")
        self.assertEqual(browser["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertEqual(y["jobs"]["browser"]["environment"]["name"], "staging")
        self.assertIn("github.ref == 'refs/heads/main'", y["jobs"]["browser"]["if"])


if __name__ == "__main__":
    unittest.main()
