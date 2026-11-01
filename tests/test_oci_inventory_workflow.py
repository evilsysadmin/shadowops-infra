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

    def test_full_oci_suite_has_one_owner_and_probes_use_narrow_contracts(self):
        workflows = ROOT / ".github/workflows"
        owner = (workflows / "oci-inventory.yml").read_text()
        host = (workflows / "oci-host-probe.yml").read_text()
        ports = (workflows / "oci-chronicles-ports.yml").read_text()
        suite = "-p 'test_oci_*.py'"
        self.assertIn(suite, owner)
        self.assertNotIn(suite, host)
        self.assertNotIn(suite, ports)
        self.assertIn("-p 'test_oci_host_probe.py'", host)
        self.assertIn("-p 'test_oci_probe_admission.py'", host)
        self.assertIn("-p 'test_oci_chronicles_ports_probe.py'", ports)
        # Shared-suite owner must rerun when a consumer workflow changes.
        for path in ("oci-host-probe.yml", "oci-chronicles-ports.yml",
                     "test_oci_inventory_workflow.py"):
            self.assertIn(path, owner)

    def test_no_host_mutation_or_secret_output(self):
        workflow = (ROOT / ".github/workflows/oci-inventory.yml").read_text()
        for forbidden in ("sudo ", "terraform apply", "gh secret set", "docker compose up",
                          "oci_host_probe.py run", "printenv", "env | sort"):
            self.assertNotIn(forbidden, workflow)

if __name__ == "__main__":
    unittest.main()
