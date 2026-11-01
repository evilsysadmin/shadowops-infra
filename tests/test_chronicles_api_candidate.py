"""Offline checks for the exact Chronicles API candidate selector."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/chronicles_api_candidate.sh"
WORKFLOW = ROOT / ".github/workflows/chronicles-api-staging.yml"
SHA = "a" * 40


class CandidateTests(unittest.TestCase):
    def run_gate(self, *, requested="", main=SHA, only="false", target="staging",
                 event="push", source="ready", receipt="1", gh_exit="0"):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp)
            gh = bin_dir / "gh"
            gh.write_text('#!/bin/sh\n'
                          '[ "$FAKE_GH_EXIT" = 0 ] || exit "$FAKE_GH_EXIT"\n'
                          'case "$*" in\n'
                          '  *chronicles-of-matthias/commits/main*) printf "%s\\n" "$FAKE_SHA";;\n'
                          '  *) exit 9;;\n'
                          'esac\n')
            gh.chmod(0o755)
            py = bin_dir / "python3"
            py.write_text('#!/bin/sh\n'
                          'case "$1" in\n'
                          '  scripts/chronicles_source_ci.py) printf "%s\\n" "$FAKE_CI";;\n'
                          '  scripts/chronicles_api_before_pages.py) exit "$FAKE_RECEIPT";;\n'
                          '  *) exit 9;;\n'
                          'esac\n')
            py.chmod(0o755)
            output = bin_dir / "output"
            output.write_text("")
            env = {**os.environ,
                   "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   "GITHUB_OUTPUT": str(output),
                   "GH_TOKEN": "synthetic-readonly", "TARGET_ENV": target,
                   "REQUESTED_SHA": requested, "ONLY_IF_NEW": only,
                   "GITHUB_EVENT_NAME": event, "FAKE_SHA": main,
                   "FAKE_GH_EXIT": gh_exit, "FAKE_CI": source,
                   "FAKE_RECEIPT": receipt}
            run = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=5)
            return run, output.read_text().splitlines()

    def test_automatic_current_main_deploys_only_with_missing_receipt(self):
        for receipt, wanted in (("0", "false"), ("1", "true")):
            with self.subTest(receipt=receipt):
                run, output = self.run_gate(receipt=receipt)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(output, ["sha=" + SHA, "deploy_needed=" + wanted])

    def test_internal_dispatch_skips_superseded_requested_sha(self):
        run, output = self.run_gate(requested="b" * 40, only="true",
                                    event="workflow_dispatch")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, ["sha=" + "b" * 40, "deploy_needed=false"])
        self.assertIn("CHRONICLES_API_DISPATCH_SUPERSEDED", run.stdout)

    def test_missing_source_ci_skips_automatic_but_fails_manual(self):
        run, output = self.run_gate(source="pending")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, ["sha=" + SHA, "deploy_needed=false"])
        run, output = self.run_gate(source="pending", event="workflow_dispatch")
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(output, ["sha=" + SHA])

    def test_manual_force_bypasses_existing_receipt_not_source_admission(self):
        run, output = self.run_gate(event="workflow_dispatch", receipt="0")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, ["sha=" + SHA, "deploy_needed=true"])
        run, output = self.run_gate(event="workflow_dispatch", only="true",
                                    requested=SHA, receipt="0")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, ["sha=" + SHA, "deploy_needed=false"])

    def test_receipt_errors_fail_closed(self):
        run, output = self.run_gate(receipt="7")
        self.assertEqual(run.returncode, 7)
        self.assertEqual(output, ["sha=" + SHA])
        self.assertIn("CHRONICLES_API_RECEIPT_CHECK_INCONCLUSIVE", run.stderr)

    def test_production_requires_explicit_exact_sha(self):
        run, output = self.run_gate(target="production")
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(output, [])
        run, output = self.run_gate(target="production", requested=SHA)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, ["sha=" + SHA, "deploy_needed=true"])

    def test_bad_sha_and_failed_github_queries_rejected(self):
        for opts in ({"main": "bad"}, {"main": ""}, {"main": "A" * 40},
                     {"gh_exit": "7"}, {"requested": "b" * 39}):
            with self.subTest(opts=opts):
                run, output = self.run_gate(**opts)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(output, [])

    def test_workflow_requires_protected_main_and_preserves_attestation(self):
        txt = WORKFLOW.read_text(encoding="utf-8")
        admit = txt.split("\n  admit:\n", 1)[1].split("\n  deploy:\n", 1)[0]
        self.assertIn("needs.contracts.result == 'success'", admit)
        self.assertIn("github.ref == 'refs/heads/main'", admit)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", admit)
        self.assertIn("run: bash scripts/chronicles_api_candidate.sh", admit)
        self.assertIn("ONLY_IF_NEW: ${{ inputs.action == 'grant-admin' && 'false'", admit)
        self.assertIn("gh attestation verify", admit)
        self.assertIn("bash -n scripts/chronicles_api_candidate.sh", txt)
        self.assertIn("test_chronicles_api_candidate.py", txt)
        self.assertIn("scripts/chronicles_api_candidate.sh", txt.split("  pull_request:", 1)[1].split("  push:", 1)[0])
        self.assertLess(admit.index("actions/checkout@v4"),
                        admit.index("run: bash scripts/chronicles_api_candidate.sh"))
        self.assertLess(admit.index("run: bash scripts/chronicles_api_candidate.sh"),
                        admit.index("gh attestation verify"))


if __name__ == "__main__":
    unittest.main()
