"""A superseded staging Pages release must finish as a safe no-op, never a false-red."""
import os
import pathlib
import subprocess
import tempfile
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/chronicles-pages-release.yml"
SOURCE = "a" * 40
OWNER = "b" * 40


class PagesEarlyStalenessGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        cls.steps = wf["jobs"]["release"]["steps"]
        cls.preflight = cls.steps[0]

    def test_gates_all_source_checkout_build_publish_and_receipts(self):
        self.assertEqual(self.preflight["id"], "entry_freshness")
        self.assertIn("chronicles-of-matthias/commits/main", self.preflight["run"])
        self.assertIn("shadowops-infra/commits/main", self.preflight["run"])
        self.assertIn("CHRONICLES_PAGES_OBSOLETE_ENTRY", self.preflight["run"])
        self.assertGreater(len(self.steps), 20)
        for step in self.steps[1:]:
            with self.subTest(step=step.get("name", step.get("uses"))):
                self.assertIn("steps.entry_freshness.outputs.fresh == 'true'", step.get("if", ""))
        wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(wf["jobs"]["release"]["outputs"]["verified"],
                         "${{ steps.source_freshness.outputs.fresh }}")
        self.assertIn("steps.source_freshness.outputs.fresh == 'true'",
                      self.steps[-1]["if"])

    def run_preflight(self, *, owner=OWNER, source=SOURCE,
                      actual_owner=OWNER, actual_source=SOURCE,
                      repository="evilsysadmin/shadowops-infra",
                      gh_fail=False):
        with tempfile.TemporaryDirectory() as temp:
            folder = pathlib.Path(temp)
            gh = folder / "gh"
            gh.write_text(
                '#!/bin/sh\n'
                'if [ "$MOCK_GH_FAIL" = true ]; then exit 7; fi\n'
                'case "$*" in\n'
                '  *shadowops-infra*) printf "%s\\n" "$MOCK_OWNER_SHA";;\n'
                '  *chronicles-of-matthias*) printf "%s\\n" "$MOCK_SOURCE_SHA";;\n'
                '  *) exit 8;;\n'
                'esac\n')
            gh.chmod(0o755)
            out, summary = folder / "output", folder / "summary"
            out.write_text("")
            summary.write_text("")
            env = {**os.environ,
                   "PATH": str(folder) + os.pathsep + os.environ.get("PATH", ""),
                   "GH_TOKEN": "synthetic-readonly",
                   "GITHUB_REPOSITORY": repository,
                   "GITHUB_REF": "refs/heads/main",
                   "GITHUB_EVENT_NAME": "workflow_dispatch",
                   "GITHUB_SHA": owner,
                   "ADMITTED_SHA": source,
                   "MOCK_OWNER_SHA": actual_owner,
                   "MOCK_SOURCE_SHA": actual_source,
                   "MOCK_GH_FAIL": str(gh_fail).lower(),
                   "GITHUB_OUTPUT": str(out),
                   "GITHUB_STEP_SUMMARY": str(summary)}
            run = subprocess.run(["bash", "-c", self.preflight["run"]],
                                 env=env, capture_output=True, text=True,
                                 check=False, timeout=5)
            return run, out.read_text(), summary.read_text()

    def test_current_source_keeps_strict_owner_admission(self):
        run, output, summary = self.run_preflight()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output.strip(), "fresh=true")
        self.assertEqual(summary, "")

    def test_superseded_owner_or_source_skips_without_receipts(self):
        for changed in ({"actual_owner": "c" * 40},
                        {"actual_source": "d" * 40},
                        {"actual_owner": "c" * 40, "actual_source": "d" * 40}):
            with self.subTest(changed=changed):
                run, output, summary = self.run_preflight(**changed)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(output.strip(), "fresh=false")
                self.assertIn("superseded before checkout", summary)
                self.assertIn("CHRONICLES_PAGES_OBSOLETE_ENTRY", run.stdout)

    def test_invalid_context_sha_or_unavailable_github_fails_closed(self):
        for args in (
            {"repository": "foreign/repo"},
            {"owner": "not-a-sha"},
            {"source": "main"},
            {"actual_owner": "invalid"},
            {"actual_source": ""},
            {"gh_fail": True},
        ):
            with self.subTest(args=args):
                run, output, summary = self.run_preflight(**args)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(summary, "")


if __name__ == "__main__":
    unittest.main()
