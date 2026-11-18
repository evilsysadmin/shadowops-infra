"""Contract for first one-time Pages deploy: no auth bypass or DNS operations."""
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / ".github/workflows/bridgesquad-pages-bootstrap.yml"


class BootstrapWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PATH.read_text(encoding="utf-8")
        cls.contracts, cls.job = cls.text.split("\n  bootstrap:\n", 1)

    def test_no_upload_or_secret_access_from_untrusted_prs(self):
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertIn("github.event_name == 'push'", self.job)
        self.assertIn("needs: contracts", self.job)
        self.assertNotIn("github.event_name == 'pull_request'", self.job)
        self.assertNotIn("workflow_dispatch", self.job)
        self.assertNotIn("secrets.CLOUDFLARE", self.contracts)
        self.assertIn("environment:\n      name: staging", self.job)
        self.assertIn("CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}", self.job)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}", self.job)
        self.assertIn("GH_TOKEN: ${{ github.token }}", self.job)
        self.assertNotIn("\\${{", self.text)

    def test_one_time_nonempty_project_guard_before_any_upload(self):
        self.assertIn("bridgesquad_alias_bootstrap.py preflight", self.job)
        self.assertEqual(self.job.count("bridgesquad_alias_bootstrap.py preflight"), 2)
        ordered = (
            "bridgesquad_alias_bootstrap.py preflight",
            "source.admit(reader,sha)",
            "bridgesquad_source_admission.py verify-archive",
            "bridgesquad_release_package.py prepare",
            "bridgesquad_release_package.py verify",
            "gh api repos/evilsysadmin/shadowops-infra/commits/main",
            "wrangler@4.127.1 pages deploy",
            "bridgesquad_alias_bootstrap.py postflight",
        )
        seen = [self.job.index(item) for item in ordered]
        self.assertEqual(seen, sorted(seen))

    def test_only_exact_pages_direct_upload_never_mutates_dns_or_id(self):
        for required in (
            "--project-name bridgesquad-production",
            "--branch main",
            '--commit-hash "$GAME_SHA"',
            "bridgesquad_alias_bootstrap.py postflight",
            "github.ref == 'refs/heads/main'",
        ):
            self.assertIn(required, self.job)
        for forbidden in (
            "dns_records", "pages/projects/other", "pages/domains",
            "OCI_PRIVATE_KEY", "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL",
            "pages domain", "api.cloudflare.com", "workers deploy",
            "actions/deploy-pages",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden.lower(), self.job.lower())
        self.assertIn('CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}', self.job)

    def test_every_alias_and_deployment_sha_must_pass_before_success_receipt(self):
        self.assertIn("bridgesquad_alias_bootstrap.py postflight", self.job)
        self.assertIn("test \"$(gh api repos/evilsysadmin/matthias-bridge-squad/commits/main --jq .sha)\"",self.job)
        self.assertIn("echo 'BRIDGESQUAD_PAGES_LOCKED aliases=404", self.job)
        self.assertIn("exit 1", self.job)
        self.assertIn("for attempt in 1 2 3 4 5 6", self.job)
        self.assertNotIn("continue-on-error", self.job)


if __name__ == "__main__":
    unittest.main()
