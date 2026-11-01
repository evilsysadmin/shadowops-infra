"""Offline contract for Chronicles Pages candidate selection after YAML extraction.

The mocks intercept only gh/python entry points; no HTTP, credentials or
Cloudflare are contacted. The workflow still owns protected-main event gates.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/chronicles_pages_candidate.sh"
WORKFLOW = ROOT / ".github/workflows/chronicles-pages-release.yml"
SHA = "a" * 40


class PagesCandidateContract(unittest.TestCase):
    def run_gate(self, *, live_sha=SHA, event="push", only_if_new="false",
                 requested="", source_verdict="ready", receipt_status="1",
                 gh_status="0", source_status="0"):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            bin_dir = folder / "bin"
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(
                "#!/bin/sh\n"
                "if [ \"$MOCK_GH_STATUS\" != 0 ]; then exit \"$MOCK_GH_STATUS\"; fi\n"
                "case \"$*\" in\n"
                "  *chronicles-of-matthias/commits/main*) printf '%s\\n' \"$MOCK_SHA\";;\n"
                "  *) exit 9;;\n"
                "esac\n", encoding="utf-8")
            gh.chmod(0o755)
            python = bin_dir / "python3"
            python.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  scripts/chronicles_source_ci.py)\n"
                "    [ \"$MOCK_SOURCE_STATUS\" = 0 ] || exit \"$MOCK_SOURCE_STATUS\"\n"
                "    printf '%s\\n' \"$MOCK_SOURCE_VERDICT\";;\n"
                "  scripts/chronicles_pages_verified_receipt.py)\n"
                "    exit \"$MOCK_RECEIPT_STATUS\";;\n"
                "  *) exit 9;;\n"
                "esac\n", encoding="utf-8")
            python.chmod(0o755)
            output = folder / "output"
            output.write_text("", encoding="utf-8")
            env = {**os.environ,
                   "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   "GH_TOKEN": "synthetic-readonly",
                   "GITHUB_OUTPUT": str(output),
                   "GITHUB_EVENT_NAME": event,
                   "REQUESTED_SHA": requested,
                   "ONLY_IF_NEW": only_if_new,
                   "MOCK_SHA": live_sha,
                   "MOCK_GH_STATUS": gh_status,
                   "MOCK_SOURCE_STATUS": source_status,
                   "MOCK_SOURCE_VERDICT": source_verdict,
                   "MOCK_RECEIPT_STATUS": receipt_status}
            result = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=5,
                                    check=False)
            return result, output.read_text(encoding="utf-8").splitlines()

    def test_automatic_current_main_with_missing_receipt_publishes(self):
        result, output = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=true"])

    def test_trusted_matching_receipt_skips_automatic_deploy(self):
        result, output = self.run_gate(receipt_status="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=false"])

    def test_internal_dispatch_cannot_publish_superseded_requested_sha(self):
        result, output = self.run_gate(event="workflow_dispatch",
                                       only_if_new="true", requested="b" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=false"])
        self.assertIn("CHRONICLES_PAGES_DISPATCH_SUPERSEDED", result.stdout)

    def test_automatic_pending_source_ci_skips_but_manual_fails_closed(self):
        result, output = self.run_gate(source_verdict="pending")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=false"])
        result, output = self.run_gate(event="workflow_dispatch",
                                       source_verdict="pending")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, ["source_sha=" + SHA])
        self.assertIn("source CI is not fully green", result.stderr)

    def test_manual_force_redeploy_bypasses_receipt_but_not_source_ci(self):
        result, output = self.run_gate(event="workflow_dispatch",
                                       receipt_status="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=true"])
        result, output = self.run_gate(event="workflow_dispatch",
                                       only_if_new="true", requested=SHA,
                                       receipt_status="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, ["source_sha=" + SHA, "publish=false"])

    def test_receipt_transport_error_fails_closed(self):
        result, output = self.run_gate(receipt_status="7")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(output, ["source_sha=" + SHA])
        self.assertIn("CHRONICLES_PAGES_RECEIPT_CHECK_INCONCLUSIVE", result.stderr)

    def test_malformed_sha_or_failed_live_lookups_rejected(self):
        for changes in ({"live_sha": "main"}, {"live_sha": "A" * 40},
                        {"live_sha": ""}, {"gh_status": "7"},
                        {"source_status": "3"}):
            with self.subTest(changes=changes):
                result, output = self.run_gate(**changes)
                self.assertNotEqual(result.returncode, 0)
                if changes.get("source_status"):
                    self.assertEqual(output, ["source_sha=" + SHA])
                else:
                    self.assertEqual(output, [])

    def test_workflow_executes_script_after_checkout_and_preserves_outputs(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        candidate = workflow.split("\n  staging-candidate:\n", 1)[1].split("\n  api-ready:\n", 1)[0]
        self.assertIn("if: >-", candidate)
        self.assertIn("github.ref == 'refs/heads/main'", candidate)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", candidate)
        self.assertIn("REQUESTED_SHA: ${{ inputs.source_sha }}", candidate)
        self.assertIn("ONLY_IF_NEW: ${{ inputs.only_if_new || 'false' }}", candidate)
        self.assertIn("publish: ${{ steps.check.outputs.publish }}", candidate)
        self.assertIn("source_sha: ${{ steps.check.outputs.source_sha }}", candidate)
        self.assertLess(candidate.index("actions/checkout@v4"),
                        candidate.index("run: bash scripts/chronicles_pages_candidate.sh"))
        self.assertIn("bash -n scripts/chronicles_pages_candidate.sh", workflow)
        self.assertIn("test_chronicles_pages_candidate.py", workflow)
        self.assertIn("scripts/chronicles_pages_candidate.sh", workflow.split("  pull_request:", 1)[1].split("  push:", 1)[0])


if __name__ == "__main__":
    unittest.main()
