"""Offline regression for source freshness at two independent Pages boundaries.

Neither gate deploys; the just-in-time check inside wrangler's publish step
must remain a distinct fail-closed admission.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/chronicles_pages_source_freshness.sh"
WORKFLOW = ROOT / ".github/workflows/chronicles-pages-release.yml"
SHA = "a" * 40


class FreshnessGates(unittest.TestCase):
    def run_gate(self, phase, *, admitted=SHA, current=SHA, fail_gh=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            fake = folder / "gh"
            fake.write_text(
                '#!/bin/sh\n'
                'if [ "$FAKE_GH_FAIL" = true ]; then exit 7; fi\n'
                'case "$*" in\n'
                '  *chronicles-of-matthias/commits/main*) printf "%s\\n" "$FAKE_MAIN_SHA";;\n'
                '  *) exit 8;;\n'
                'esac\n', encoding="utf-8")
            fake.chmod(0o755)
            output = folder / "output"
            summary = folder / "summary"
            output.write_text("", encoding="utf-8")
            summary.write_text("", encoding="utf-8")
            env = {**os.environ,
                   "PATH": str(folder) + os.pathsep + os.environ.get("PATH", ""),
                   "GH_TOKEN": "synthetic-readonly",
                   "ADMITTED_SHA": admitted,
                   "FAKE_MAIN_SHA": current,
                   "FAKE_GH_FAIL": str(fail_gh).lower(),
                   "GITHUB_OUTPUT": str(output),
                   "GITHUB_STEP_SUMMARY": str(summary)}
            result = subprocess.run(
                ["bash", str(SCRIPT), phase], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=5)
            return result, output.read_text(encoding="utf-8").splitlines(), \
                summary.read_text(encoding="utf-8")

    def test_both_phases_preserve_exact_sha_success(self):
        for phase in ("before-publish", "after-smoke"):
            with self.subTest(phase=phase):
                result, output, summary = self.run_gate(phase)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, ["fresh=true"])
                self.assertEqual(summary, "")

    def test_superseded_phases_are_successful_no_ops_without_receipts(self):
        for phase, marker, phrase in (
            ("before-publish", "CHRONICLES_PAGES_SUPERSEDED_BEFORE_PUBLISH",
             "superseded before Pages mutations"),
            ("after-smoke", "CHRONICLES_PAGES_SUPERSEDED_AFTER_SMOKE",
             "superseded after public smoke"),
        ):
            with self.subTest(phase=phase):
                result, output, summary = self.run_gate(phase, current="b" * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, ["fresh=false"])
                self.assertIn(marker, result.stdout)
                self.assertIn(phrase, summary)
                self.assertNotIn("verified=true", summary)

    def test_invalid_admitted_sha_fails_closed_before_gh(self):
        for phase in ("before-publish", "after-smoke"):
            for sha in ("", "main", "A" * 40, "a" * 39):
                with self.subTest(phase=phase, sha=sha):
                    result, output, summary = self.run_gate(phase, admitted=sha)
                    self.assertEqual(result.returncode, 64)
                    self.assertEqual(output, [])
                    self.assertEqual(summary, "")
                    self.assertIn("CHRONICLES_PAGES_INVALID_ADMITTED_SHA", result.stderr)

    def test_bad_current_sha_and_github_outage_fail_closed(self):
        for phase in ("before-publish", "after-smoke"):
            for current in ("", "bad-current", "B" * 40):
                with self.subTest(phase=phase, current=current):
                    result, output, summary = self.run_gate(phase, current=current)
                    self.assertEqual(result.returncode, 65)
                    self.assertEqual(output, [])
                    self.assertEqual(summary, "")
                    self.assertIn("CHRONICLES_PAGES_INVALID_CURRENT_MAIN_SHA", result.stderr)
            result, output, summary = self.run_gate(phase, fail_gh=True)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(output, [])
            self.assertEqual(summary, "")

    def test_invalid_phase_never_contacts_github_or_issues_receipt(self):
        result, output, summary = self.run_gate("release", admitted="invalid")
        self.assertEqual(result.returncode, 64)
        self.assertEqual(output, [])
        self.assertEqual(summary, "")
        self.assertIn("CHRONICLES_PAGES_INVALID_FRESHNESS_PHASE", result.stderr)

    def test_workflow_retains_three_distinct_phase_boundaries(self):
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["release"]["steps"]
        by_name = {step.get("name", ""): step for step in steps}
        pre = by_name["Skip superseded source before Pages mutations"]
        post = by_name["Reject superseded source before writing verified receipt"]
        publish = by_name["Publish exact source SHA to the isolated Pages project"]
        self.assertEqual(pre["id"], "source_pre_publish")
        self.assertEqual(post["id"], "source_freshness")
        self.assertEqual(pre["run"], "bash scripts/chronicles_pages_source_freshness.sh before-publish")
        self.assertEqual(post["run"], "bash scripts/chronicles_pages_source_freshness.sh after-smoke")
        self.assertEqual(pre["env"]["ADMITTED_SHA"],
                         "${{ steps.source.outputs.sha }}")
        self.assertEqual(post["env"]["ADMITTED_SHA"],
                         "${{ steps.source.outputs.sha }}")
        self.assertLess(steps.index(pre), steps.index(publish))
        self.assertLess(steps.index(publish),
                        steps.index(by_name["Real public browser smoke (desktop, mobile, login, update deferral)"]))
        self.assertLess(steps.index(by_name["Real public browser smoke (desktop, mobile, login, update deferral)"]),
                        steps.index(post))
        self.assertIn("CHRONICLES_PAGES_SUPERSEDED_AT_DEPLOY", publish["run"])
        self.assertIn('gh api repos/evilsysadmin/chronicles-of-matthias/commits/main',
                      publish["run"])
        self.assertIn("wrangler@4.127.1 pages deploy", publish["run"])
        self.assertLess(publish["run"].index("CHRONICLES_PAGES_SUPERSEDED_AT_DEPLOY"),
                        publish["run"].index("wrangler@4.127.1 pages deploy"))
        self.assertIn("steps.source_pre_publish.outputs.fresh == 'true'", publish["if"])
        verified = by_name["Record the verified Chronicles Pages source generation"]
        self.assertIn("steps.source_freshness.outputs.fresh == 'true'", verified["if"])
        txt = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("scripts/chronicles_pages_source_freshness.sh",
                      txt.split("  pull_request:", 1)[1].split("  push:", 1)[0])
        self.assertIn("bash -n scripts/chronicles_pages_source_freshness.sh", txt)


if __name__ == "__main__":
    unittest.main()
