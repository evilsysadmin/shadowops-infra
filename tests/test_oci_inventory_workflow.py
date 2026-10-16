"""Static contract for the first credential-backed OCI read-only verification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class TestTrustedOCIInventoryWorkflow(unittest.TestCase):
    def test_live_run_only_from_protected_main_events(self):
        text = (ROOT / ".github/workflows/oci-inventory.yml").read_text()
        self.assertIn("if: (github.event_name == 'workflow_dispatch' || github.event_name == 'push')", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", text)
        self.assertIn("needs: contracts", text)
        self.assertIn("paths:", text)
        self.assertIn("run: python scripts/oci_control_plane.py inventory", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("issues:", text)

    def test_no_host_mutation_or_secret_output(self):
        workflow = (ROOT / ".github/workflows/oci-inventory.yml").read_text()
        for forbidden in ("sudo ", "terraform apply", "gh secret set", "docker compose up",
                          "oci_host_probe.py run", "printenv", "env | sort"):
            self.assertNotIn(forbidden, workflow)

if __name__ == "__main__":
    unittest.main()
