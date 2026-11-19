"""Contract for the daily / main-only Bridge Squad locked-alias audit."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / ".github/workflows/bridgesquad-alias-watchdog.yml"
AUDITOR = ROOT / "scripts/bridgesquad_alias_watchdog.py"


class AliasWatchdogWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = FLOW.read_text(encoding="utf-8")
        cls.contracts, cls.audit = cls.text.split("\n  audit:\n", 1)
        cls.code = AUDITOR.read_text(encoding="utf-8")

    def test_only_protected_main_and_daily_schedule_can_access_cloudflare(self):
        self.assertIn("schedule:\n    - cron: '31 7 * * *'", self.text)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.audit)
        self.assertIn("github.ref == 'refs/heads/main'", self.audit)
        for event in ("push", "schedule", "workflow_dispatch"):
            self.assertIn("github.event_name == '" + event + "'", self.audit)
        self.assertNotIn("github.event_name == 'pull_request'", self.audit)
        self.assertIn("needs: contracts", self.audit)
        self.assertIn("environment:\n      name: staging", self.audit)

    def test_secrets_only_under_protected_audit_and_no_deploy_operations(self):
        self.assertNotIn("secrets.CLOUDFLARE", self.contracts)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}", self.audit)
        self.assertIn("CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}", self.audit)
        self.assertNotIn("continue-on-error", self.text)
        self.assertNotIn("\\${{", self.text)
        self.assertIn("python3 scripts/bridgesquad_alias_watchdog.py audit", self.audit)
        for forbidden in ("wrangler", "api.cloudflare.com", "gh api", "OCI_PRIVATE_KEY",
                          "DNS", "deploy-pages", "pages deploy"):
            if forbidden == "DNS":
                # Only a human-readable no-DNS reassurance is allowed.
                self.assertNotIn("/dns_records", self.audit)
            else:
                self.assertNotIn(forbidden.lower(), self.audit.lower())

    def test_completed_one_time_pages_publisher_is_permanently_disabled(self):
        old = (ROOT / ".github/workflows/bridgesquad-pages-bootstrap.yml").read_text(encoding="utf-8")
        bootstrap = old.split("\n  bootstrap:\n", 1)[1]
        self.assertIn("false &&", bootstrap)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", bootstrap)
        self.assertIn("github.ref == 'refs/heads/main'", bootstrap)
        self.assertIn("run: python3 scripts/bridgesquad_alias_watchdog.py audit", self.audit)

    def test_watchdog_uses_live_project_and_existing_denial_contract(self):
        self.assertIn("bootstrap.postflight(client, sha, status=probe)", self.code)
        self.assertIn("client.get(path)", self.code)
        self.assertIn("int(result[\"aliases\"]) < 2", self.code)
        self.assertNotIn("subprocess.", self.code)
        self.assertNotIn("requests.post", self.code)


if __name__ == "__main__":
    unittest.main()
