"""Static fail-closed contract: an opt-in protected promotion, never a PR deploy."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / ".github/workflows/bridgesquad-production-release.yml"
RELEASE = ROOT / "scripts/bridgesquad_production_release.py"


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.yaml = FLOW.read_text(encoding="utf-8")
        cls.contracts, rest = cls.yaml.split("\n  prepare:\n", 1)
        cls.prepare, cls.publish = rest.split("\n  publish:\n", 1)
        cls.release = RELEASE.read_text(encoding="utf-8")

    def test_no_push_cron_or_pr_production_publish(self):
        self.assertIn("  pull_request:", self.yaml)
        self.assertIn("  workflow_dispatch:", self.yaml)
        self.assertNotIn("  push:", self.yaml)
        self.assertNotIn("  schedule:", self.yaml)
        for job in (self.prepare, self.publish):
            self.assertIn("github.event_name == 'workflow_dispatch'", job)
            self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", job)
            self.assertIn("github.ref == 'refs/heads/main'", job)
            self.assertIn("inputs.confirm == 'RELEASE_BRIDGESQUAD_PRODUCTION'", job)
            self.assertIn("needs:", job)
            self.assertNotIn("github.event_name == 'pull_request'", job)
        for field in ("target_sha:", "expected_live_sha:", "confirm:"):
            self.assertIn(field, self.contracts)
        self.assertIn("cancel-in-progress: false", self.yaml)

    def test_secrets_only_in_protected_production_job(self):
        self.assertNotIn("secrets.", self.contracts)
        self.assertNotIn("secrets.", self.prepare)
        self.assertIn("environment:\n      name: bridgesquad-production", self.publish)
        self.assertIn("CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}", self.publish)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}", self.publish)
        self.assertNotIn("name: staging", self.yaml)
        self.assertNotIn("continue-on-error", self.yaml)
        self.assertIn("permissions:\n  contents: read\n  actions: read", self.yaml)

    def test_immutable_source_and_real_sealed_browser_before_release(self):
        required = (
            "source.admit(source.GithubReader(os.environ['GH_TOKEN'])",
            "gh api \"repos/evilsysadmin/matthias-bridge-squad/actions/artifacts/$ARTIFACT_ID/zip\"",
            "bridgesquad_source_admission.py verify-archive",
            "bridgesquad_release_package.py prepare",
            "bridgesquad_release_package.py verify",
            "bridgesquad_sealed_worker_browser.py",
            "bridgesquad_source_admission.py check \"$TARGET_SHA\"",
            "actions/upload-artifact@v4",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.prepare)
        sequence = ["source.admit(", "gh api", "verify-archive", "release_package.py prepare",
                    "release_package.py verify", "sealed_worker_browser.py",
                    "source_admission.py check", "actions/upload-artifact@v4"]
        indexes = [self.prepare.index(item) for item in sequence]
        self.assertEqual(indexes, sorted(indexes))
        self.assertIn("if-no-files-found: error", self.prepare)
        self.assertIn("retention-days: 1", self.prepare)
        self.assertIn("persist-credentials: false", self.prepare)

    def test_publish_rechecks_environment_sha_worker_and_guest_before_upload(self):
        for required in (
            "actions/download-artifact@v4",
            "bridgesquad_release_package.py verify",
            "bridgesquad_source_admission.py check",
            "commits/main --jq .sha",
            "bridgesquad_production_release.py preflight \"$LIVE_SHA\" \"$TARGET_SHA\"",
            "npx --yes wrangler@4.127.1 pages deploy",
            "--project-name bridgesquad-production",
            "--branch main",
            "--commit-hash \"$TARGET_SHA\"",
            "bridgesquad_production_release.py postflight \"$TARGET_SHA\" \"$PRIOR_DEPLOYMENT_ID\"",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.publish)
        self.assertLess(self.publish.index("actions/download-artifact@v4"),
                        self.publish.index("bridgesquad_release_package.py verify"))
        self.assertLess(self.publish.index("release_package.py verify"),
                        self.publish.index("production_release.py preflight"))
        self.assertLess(self.publish.index("production_release.py preflight"),
                        self.publish.index("wrangler@4.127.1 pages deploy"))
        self.assertLess(self.publish.index("wrangler@4.127.1 pages deploy"),
                        self.publish.index("production_release.py postflight"))
        self.assertIn("steps.before.outputs.prior_deployment_id", self.publish)
        self.assertIn("guest=401", self.publish)
        self.assertNotIn("wrangler pages project create", self.publish)
        self.assertNotIn("dns_records", self.publish)
        self.assertNotIn("secret put", self.publish)
        self.assertNotIn("github.io", self.yaml)
        self.assertNotIn("legacy_pages_guard", self.yaml)

    def test_admission_only_reads_provider_and_rejects_unbound_identity(self):
        for required in ("quarantine.project(client, allow_bound=True)",
                         "proof.postflight(client, deployed_sha",
                         "_deployment_id(canonical.get(\"id\"))",
                         "if live_sha == target_sha:",
                         "if result[\"source_sha\"] != live_sha:",
                         "if result[\"source_sha\"] != target_sha:",
                         "if result[\"deployment_id\"] == previous_id:"):
            with self.subTest(required=required):
                self.assertIn(required, self.release)
        for forbidden in ("urllib.request.Request", "method=\"PATCH\"",
                          "method=\"POST\"", "wrangler", "subprocess", "cloudflared"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.release)


if __name__ == "__main__":
    unittest.main()
