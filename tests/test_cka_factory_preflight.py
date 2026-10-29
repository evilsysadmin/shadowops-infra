"""CKA factory staging preflight is read-only and manual, not a deployment."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/cka-factory-preflight.yml"
DOC = ROOT / "docs/cka-factory-staging.md"


class TestCKAFactoryStagingPreflight(unittest.TestCase):
    def test_manual_protected_main_only(self):
        content = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", content)
        self.assertIn("source_sha:", content)
        self.assertIn("github.event_name == 'workflow_dispatch'", content)
        self.assertIn("github.ref == 'refs/heads/main'", content)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", content)
        self.assertIn("needs: contracts", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertNotIn("pull_request_target", content)

    def test_exact_sha_handshake_and_no_cloudflare_or_oci_secret_access(self):
        content = WORKFLOW.read_text()
        self.assertIn("repos/evilsysadmin/cka-exam-simulator/commits/main", content)
        self.assertIn('"$REQUESTED_SHA" == "$main_sha"', content)
        self.assertIn("ref: ${{ steps.source.outputs.sha }}", content)
        self.assertIn("git -C cka-source rev-parse HEAD", content)
        self.assertIn("CKA_FACTORY_SOURCE_SUPERSEDED", content)
        self.assertIn("CKA_FACTORY_INFRA_SOURCE_SUPERSEDED", content)
        self.assertIn("CLOUDFLARE_API_TOKEN: ''", content)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID: ''", content)
        self.assertIn("cka_sim factory-run --count 1 --type deployment_scale", content)
        self.assertNotIn("cka_sim factory-run --execute", content)
        self.assertNotIn("secrets.", content)
        self.assertNotIn("OCI_PRIVATE_KEY", content)
        self.assertNotIn("terraform apply", content)
        self.assertNotIn("oci instance", content)
        self.assertNotIn("ssh ", content)
        self.assertNotIn("sudo ", content)
        self.assertNotIn("gh workflow run", content)

    def test_receipt_does_not_claim_deployment(self):
        content = WORKFLOW.read_text()
        self.assertIn('"mode": "staging-source-preflight-only"', content)
        self.assertIn('"inference_attempts": 0', content)
        self.assertIn('"oci_host_touched": False', content)
        self.assertIn('"production_changed": False', content)
        self.assertIn("CKA_FACTORY_STAGING_PREFLIGHT_OK", content)
        self.assertIn("actions/upload-artifact@v4", content)
        self.assertTrue(DOC.exists())


if __name__ == "__main__":
    unittest.main()
