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

    def test_seeded_playtest_is_scoped_to_published_staging_and_daily_manual_only(self):
        spec = yaml.load(FILE.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(spec["on"]["schedule"], [{"cron": "18 5 * * *"}])
        self.assertIn("workflow_dispatch", spec["on"])
        steps = spec["jobs"]["live"]["steps"]
        by_name = {step.get("name", ""): step for step in steps}
        playtest = by_name["Bounded autonomous playtest against published Chronicles"]
        browser = by_name["Real desktop/mobile creation and cross-device persistence"]
        self.assertGreater(steps.index(playtest), steps.index(browser))
        self.assertEqual(playtest["working-directory"], "chronicles-source/frontend")
        self.assertEqual(playtest["env"]["CHRONICLES_SOURCE_SHA"],
                         "${{ steps.release.outputs.sha }}")
        self.assertEqual(playtest["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertIn("node --check smoke/public-staging-playtest.mjs", playtest["run"])
        self.assertIn("node smoke/public-staging-playtest.mjs", playtest["run"])
        summary = by_name["Summarize player-bot health and balance observations"]
        self.assertEqual(summary["if"], "always()")
        self.assertIn("GITHUB_STEP_SUMMARY", summary["run"])
        self.assertIn("averageHpLost", summary["run"])
        captures = by_name["Keep browser captures for failures or inspection"]
        self.assertEqual(captures["if"], "always()")
        for path in ("chronicles-playtest-*.png", "chronicles-playtest-report.json"):
            self.assertIn(path, captures["with"]["path"])
        self.assertEqual(spec["jobs"]["live"]["environment"]["name"], "staging")
        self.assertEqual(spec["permissions"]["contents"], "read")
        self.assertIn("github.event_name != 'pull_request'", spec["jobs"]["live"]["if"])
        code = FILE.read_text()
        for denied in ("wrangler pages deploy", "oci_chronicles_api_release.py",
                       "CLOUDFLARE_API_TOKEN", "OCI_PRIVATE_KEY", "GH_TOKEN"):
            self.assertNotIn(denied, code)

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
