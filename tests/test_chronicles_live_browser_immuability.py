"""Contract: an independent published-site E2E must not deploy or modify shared IdP."""
from pathlib import Path
import unittest
import yaml

FILE = Path(__file__).resolve().parents[1] / ".github/workflows/chronicles-live-browser-journey.yml"

class LiveJourneySafety(unittest.TestCase):
    def test_live_browser_checks_out_exact_public_staging_sha(self):
        spec = yaml.load(FILE.read_text(), Loader=yaml.BaseLoader)
        steps = spec["jobs"]["live"]["steps"]
        named = {step.get("name", ""): step for step in steps}
        read = named["Read the actual published frontend SHA"]
        checkout = named["Checkout browser tests from the exact published revision"]
        assertion = named["Assert test checkout matches published SHA"]
        browser = named["Real desktop/mobile creation and cross-device persistence"]
        self.assertLess(steps.index(read), steps.index(checkout))
        self.assertLess(steps.index(checkout), steps.index(assertion))
        self.assertLess(steps.index(assertion), steps.index(browser))
        self.assertEqual(checkout["with"]["ref"], "${{ steps.release.outputs.sha }}")
        self.assertEqual(checkout["with"]["repository"],
                         "evilsysadmin/chronicles-of-matthias")
        self.assertEqual(checkout["with"]["persist-credentials"], "false")
        self.assertEqual(assertion["env"]["PUBLIC_SHA"], "${{ steps.release.outputs.sha }}")
        self.assertIn("rev-parse HEAD", assertion["run"])
        self.assertNotIn("ref: main", FILE.read_text())

    def test_read_only_scope(self):
        spec = yaml.load(FILE.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(spec["permissions"]["contents"], "read")
        live = spec["jobs"]["live"]
        self.assertIn("refs/heads/main", live["if"])
        self.assertIn("evilsysadmin/shadowops-infra", live["if"])
        self.assertEqual(live["environment"]["name"], "staging")
        code = FILE.read_text()
        for marker in ("release.json?probe=", "CHRONICLES_SOURCE_SHA:",
                       "CHRONICLES_STAGING_INVITE_CODE:", "node --check smoke/public-staging-journey.mjs",
                       "node smoke/public-staging-journey.mjs",
                       "node --check smoke/public-staging-combat.mjs",
                       "node smoke/public-staging-combat.mjs",
                       "chronicles-combat-*.png"):
            self.assertIn(marker, code)
        for denied in ("wrangler pages deploy", "oci_chronicles_api_release.py",
                       "CLOUDFLARE_API_TOKEN", "OCI_PRIVATE_KEY", "GH_TOKEN"):
            self.assertNotIn(denied, code)

if __name__ == "__main__":
    unittest.main()
