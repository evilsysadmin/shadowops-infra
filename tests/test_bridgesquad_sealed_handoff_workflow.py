"""Static guardrails for the non-deploying Bridge Squad source-to-Infra handoff."""
import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/bridgesquad-source-admission.yml"


class SealedHandoffWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.job = self.text.split("\n  sealed-candidate:\n", 1)[1]

    def test_handoff_is_bound_to_trusted_main_and_green_contracts(self):
        self.assertIn("needs: contracts", self.job)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertIn("github.event_name == 'push'", self.job)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.job)
        self.assertNotIn("pull_request", self.job)

    def test_exact_game_artifact_and_both_layers_of_verification(self):
        for required in (
            "source.admit(reader, sha)",
            "steps.source.outputs.artifact_id",
            "steps.source.outputs.artifact_digest",
            "gh api \"repos/evilsysadmin/matthias-bridge-squad/actions/artifacts/$ARTIFACT_ID/zip\"",
            "bridgesquad_source_admission.py verify-archive",
            "bridgesquad_release_package.py prepare",
            "bridgesquad_release_package.py verify",
            "bridgesquad_source_admission.py check \"$SOURCE_SHA\"",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.job)
        order = ["source.admit(reader, sha)", "gh api", "verify-archive",
                 "release_package.py prepare", "release_package.py verify",
                 "source_admission.py check", "actions/upload-artifact@v4"]
        offsets = [self.job.index(item) for item in order]
        self.assertEqual(offsets, sorted(offsets), "upload must follow all checks")

    def test_no_cloudflare_dns_secret_binding_or_public_delivery(self):
        for prohibited in (
            "wrangler", "deploy-pages", "cloudflare-api", "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ACCOUNT_ID", "OCI_PRIVATE_KEY",
            "actions/deploy-pages", "CF_API_TOKEN",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited.lower(), self.job.lower())
        self.assertIn("actions/upload-artifact@v4", self.job)
        self.assertIn("retention-days: 14", self.job)
        self.assertIn("persist-credentials: false", self.job)

    def test_no_pr_or_untrusted_fork_can_package_as_main(self):
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertRegex(self.job, r"\[\[ \"\$SOURCE_SHA\" =~ \^\[0-9a-f\]\{40\}\$ \]\]")
        self.assertIn("if-no-files-found: error", self.job)


if __name__ == "__main__":
    unittest.main()
