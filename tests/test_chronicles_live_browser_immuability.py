"""Contract: an independent published-site E2E must not deploy or modify shared IdP."""
from pathlib import Path
import unittest
import yaml

FILE = Path(__file__).resolve().parents[1] / ".github/workflows/chronicles-live-browser-journey.yml"

class LiveJourneySafety(unittest.TestCase):
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
