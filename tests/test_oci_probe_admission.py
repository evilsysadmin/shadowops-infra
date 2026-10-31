"""Trusted-main-only, bounded manual host probe after accredited first run.
PRs must not execute OCI Run Command, even when the workflow changes.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from oci_host_probe import HOST_COMMAND

class LiveProbeAdmission(unittest.TestCase):
    def test_trusted_main_only_and_bounded(self):
        body = (ROOT / ".github/workflows/oci-host-probe.yml").read_text()
        self.assertIn("if: github.event_name == 'workflow_dispatch'", body)
        self.assertIn("github.ref == 'refs/heads/main'", body)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", body)
        self.assertIn("needs: contracts", body)
        self.assertIn("paths:", body)
        self.assertIn("cancel-in-progress: false", body)
        self.assertIn("timeout-minutes: 12", body)
        self.assertIn("python scripts/oci_host_probe.py run", body)
        self.assertIn("permissions:\n  contents: read", body)
        self.assertNotIn("pull_request_target", body)
        self.assertNotIn("|| github.event_name == 'push'", body)

    def test_chronicles_wrapper_probe_requires_manual_protected_main_and_fresh_sha(self):
        body = (ROOT / ".github/workflows/oci-host-probe.yml").read_text()
        self.assertIn("options: [host, chronicles-wrapper]", body)
        self.assertIn("default: host", body)
        self.assertIn("if: inputs.probe != 'chronicles-wrapper'", body)
        self.assertIn("if: inputs.probe == 'chronicles-wrapper'", body)
        self.assertIn("CHRONICLES_WRAPPER_PROBE_SUPERSEDED_MAIN", body)
        self.assertIn('current="$(gh api repos/evilsysadmin/shadowops-infra/commits/main --jq .sha)"', body)
        self.assertIn('"$current" == "$GITHUB_SHA"', body)
        self.assertLess(body.index('Reject a superseded Infra main'),
                        body.index('Compare the installed Chronicles API wrapper'))
        self.assertIn("python scripts/oci_host_probe.py wrapper", body)
        self.assertIn("host/chronicles-api-deploy.py", body)
        self.assertNotIn("sudo --non-interactive", body)
        self.assertNotIn("pull_request_target", body)

    def test_fixed_host_command_remains_nonprivileged(self):
        for forbidden in ("sudo", "docker compose up", "docker compose down",
                          "systemctl restart", "terraform", "ssh ", "git fetch",
                          "OCI_PRIVATE_KEY", "JWT_SECRET"):
            self.assertNotIn(forbidden, HOST_COMMAND)
        self.assertIn("http://127.0.0.1:4000/api/ready", HOST_COMMAND)

if __name__ == "__main__":
    unittest.main()
