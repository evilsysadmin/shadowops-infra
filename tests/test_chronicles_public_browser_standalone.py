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
        self.assertIn("https://staging.chronicles.shadowops.dpdns.org/release.json", code)
        self.assertIn("--max-redirs 0", code)
        self.assertIn("--write-out '%{http_code}'", code)
        self.assertIn('[[ "$http_code" == \'200\' ]]', code)
        self.assertIn("bytes > 0 && bytes <= 65536", code)
        self.assertIn("CHRONICLES_PUBLIC_SMOKE_RELEASE_NOT_200", code)
        self.assertIn("CHRONICLES_PUBLIC_SMOKE_RELEASE_OVERSIZED", code)
        self.assertNotIn(" -fsSL", code)
        self.assertNotIn("--location", code)
        self.assertIn('[[ "$sha" =~ ^[0-9a-f]{40}$ ]]', code)
        read = names.index("Read the public SHA actually served by Pages")
        checkout_name = "Check out test scripts from the exact published Chronicles revision"
        assert_name = "Assert the source checkout matches the published SHA"
        install_name = "Install Chromium for the public smoke"
        self.assertLess(read, names.index(checkout_name))
        self.assertLess(names.index(checkout_name), names.index(assert_name))
        self.assertLess(names.index(assert_name), names.index(install_name))
        checkout = next(s for s in steps if s.get("name") == checkout_name)
        self.assertEqual(checkout["with"]["repository"], "evilsysadmin/chronicles-of-matthias")
        self.assertEqual(checkout["with"]["ref"], "${{ steps.current.outputs.sha }}")
        self.assertEqual(checkout["with"]["persist-credentials"], "false")
        self.assertNotEqual(checkout["with"]["ref"], "main")
        assertion = next(s for s in steps if s.get("name") == assert_name)
        self.assertIn('test "$(git rev-parse HEAD)" = "$PUBLIC_SHA"', assertion["run"])
        self.assertEqual(assertion["env"]["PUBLIC_SHA"], "${{ steps.current.outputs.sha }}")
        browser = next(s for s in steps if s.get("name") == "Validate the actual public Chronicles game in desktop and mobile")
        self.assertIn("smoke/public-staging.mjs", browser["run"])
        self.assertEqual(browser["env"]["CHRONICLES_SOURCE_SHA"], "${{ steps.current.outputs.sha }}")
        self.assertEqual(browser["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertEqual(y["jobs"]["browser"]["environment"]["name"], "staging")
        self.assertIn("github.ref == 'refs/heads/main'", y["jobs"]["browser"]["if"])


if __name__ == "__main__":
    unittest.main()
