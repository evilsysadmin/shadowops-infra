"""Trusted-main-only, bounded manual host probe after accredited first run.
PRs must not execute OCI Run Command, even when the workflow changes.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import textwrap
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

    @staticmethod
    def workflow_shell_step(name: str) -> str:
        text = (ROOT / ".github/workflows/oci-host-probe.yml").read_text()
        marker = "      - name: " + name + "\n"
        start = text.index(marker) + len(marker)
        start = text.index("        run: |\n", start) + len("        run: |\n")
        end = text.find("      - name:", start)
        return textwrap.dedent(text[start:] if end < 0 else text[start:end])

    def test_wrapper_report_rejects_unknown_stdout_and_preserves_probe_exit(self):
        workflow = (ROOT / ".github/workflows/oci-host-probe.yml").read_text()
        self.assertIn("Recheck protected main after Chronicles wrapper observation", workflow)
        self.assertIn("if: inputs.probe == 'chronicles-wrapper' && success()", workflow)
        self.assertLess(workflow.index("Compare the installed Chronicles API wrapper"),
                        workflow.index("Recheck protected main after Chronicles wrapper"))
        shell = self.workflow_shell_step(
            "Compare the installed Chronicles API wrapper with protected source")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_python = root / "python"
            fake_python.write_text("#!/bin/sh\n"
                                   "printf '%s' \"$PROBE_OUTPUT\"\n"
                                   "exit \"$PROBE_EXIT\"\n")
            fake_python.chmod(0o755)
            summary = root / "summary"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       GITHUB_SHA="a" * 40, GITHUB_STEP_SUMMARY=str(summary))
            for value, exitcode, ok, summary_expected in (
                ("CHRONICLES_API_WRAPPER_CURRENT", 0, True, True),
                ("CHRONICLES_API_WRAPPER_CURRENT", 1, False, True),
                ("CHRONICLES_API_WRAPPER_OUTDATED", 1, False, True),
                ("CHRONICLES_API_WRAPPER_MISSING", 1, False, True),
                ("CHRONICLES_API_WRAPPER_UNSAFE", 1, False, True),
                ("CHRONICLES_API_WRAPPER_OUTDATED", 0, False, True),
                ("CHRONICLES_API_WRAPPER_CURRENT\nSECRET=hidden", 0, False, False),
                ("CHRONICLES_API_WRAPPER_CURRENT extra", 0, False, False),
                ("", 0, False, False),
            ):
                with self.subTest(status=value[:35], exit=exitcode):
                    summary.unlink(missing_ok=True)
                    result = subprocess.run(["bash", "-c", shell], env=dict(
                        env, PROBE_OUTPUT=value, PROBE_EXIT=str(exitcode)),
                        text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, ok, result.stderr)
                    self.assertEqual(summary.exists(), summary_expected)
                    self.assertNotIn("SECRET=hidden", result.stdout + result.stderr)
                    if summary.exists():
                        report = summary.read_text()
                        self.assertIn(value, report)
                        self.assertIn("Host mutations: none", report)
                        self.assertIn("a" * 40, report)
                        self.assertNotIn("SECRET=hidden", report)

    def test_wrapper_late_main_check_fails_on_supersession_or_bad_response(self):
        script = self.workflow_shell_step(
            "Recheck protected main after Chronicles wrapper observation")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gh = root / "gh"
            gh.write_text("#!/bin/sh\nprintf '%s\n' \"$MOCK_MAIN\"\n")
            gh.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       GITHUB_SHA="a" * 40, GITHUB_STEP_SUMMARY=str(root / "summary"))
            for main, ok in (("a" * 40, True), ("b" * 40, False),
                             ("bad", False), ("", False)):
                with self.subTest(main=main[:10]):
                    result = subprocess.run(["bash", "-c", script],
                                            env=dict(env, MOCK_MAIN=main),
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, ok, result.stderr)
                    if not ok:
                        self.assertIn("CHRONICLES_WRAPPER_PROBE_SUPERSEDED_MAIN_AFTER_OBSERVATION",
                                      result.stderr)
                        self.assertIn("Verification invalidated",
                                      (root / "summary").read_text())

    def test_fixed_host_command_remains_nonprivileged(self):
        for forbidden in ("sudo", "docker compose up", "docker compose down",
                          "systemctl restart", "terraform", "ssh ", "git fetch",
                          "OCI_PRIVATE_KEY", "JWT_SECRET"):
            self.assertNotIn(forbidden, HOST_COMMAND)
        self.assertIn("http://127.0.0.1:4000/api/ready", HOST_COMMAND)

if __name__ == "__main__":
    unittest.main()
