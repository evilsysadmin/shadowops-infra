"""Offline contracts for the event-driven Chronicles API-to-Pages handoff."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/chronicles-pages-release.yml"
SCRIPT = ROOT / "scripts/chronicles_pages_api_gate.sh"
SHA = "a" * 40
OWNER = "b" * 40


class ApiCompletionHandoff(unittest.TestCase):
    def test_workflow_trusts_only_qualified_api_completion(self):
        workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        triggers = workflow["on"]
        self.assertEqual(triggers["workflow_run"]["types"], ["completed"])
        self.assertEqual(triggers["workflow_run"]["workflows"], [
            "ShadowOps OCI · Chronicles API (STAGING / PRODUCTION)"])
        self.assertEqual(triggers["schedule"], [{"cron": "47 * * * *"}])
        guard = workflow["jobs"]["contracts"]["if"]
        # Cheap event-level filtering must reject stale/foreign completions
        # before allocating contracts/candidate runners. This is only an
        # optimization; pages_owner_admission tests prove the deeper gate.
        for condition in (
            "github.event_name != 'workflow_run'",
            "workflow_run.conclusion == 'success'",
            "workflow_run.status == 'completed'",
            "workflow_run.head_sha == github.sha",
            "workflow_run.head_branch == 'main'",
            "workflow_run.path == '.github/workflows/chronicles-api-staging.yml'",
            "workflow_run.repository.full_name == 'evilsysadmin/shadowops-infra'",
            "workflow_run.head_repository.full_name == 'evilsysadmin/shadowops-infra'",
            "workflow_run.event == 'push'",
            "workflow_run.event == 'schedule'",
            "workflow_run.event == 'workflow_dispatch'",
        ):
            with self.subTest(condition=condition):
                self.assertIn(condition, guard)
        self.assertNotIn("workflow_run.event != 'pull_request'", guard)
        self.assertIn("github.event_name != 'workflow_run' ||", guard)
        candidate = workflow["jobs"]["staging-candidate"]["if"]
        self.assertIn("github.event_name == 'workflow_run'", candidate)
        self.assertIn("github.ref == 'refs/heads/main'", candidate)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", candidate)
        gate = workflow["jobs"]["api-ready"]
        self.assertIn("inputs.only_if_new", gate["env"]["ONLY_IF_NEW"])
        self.assertEqual(gate["if"], "needs.staging-candidate.outputs.publish == 'true'")
        self.assertIn("workflow_run", workflow["jobs"]["release"]["steps"][0]["run"])
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow["jobs"]["production"]["if"])
        self.assertIn("github.event_name == 'pull_request'",
                      workflow["concurrency"]["cancel-in-progress"])

    def run_gate(self, *, event="workflow_run", only_if_new="false",
                 code=3, owner=OWNER, source=SHA):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "bin"
            binary.mkdir()
            python = binary / "python3"
            python.write_text('#!/bin/sh\nprintf "%s\n" "$@" > "$MOCK_ARGS"\n'
                              'exit "$MOCK_CODE"\n')
            python.chmod(0o755)
            gh = binary / "gh"
            gh.write_text(
                '#!/bin/sh\ncase "$*" in\n'
                '  *shadowops-infra*) printf "%s\n" "$MOCK_OWNER";;\n'
                '  *chronicles-of-matthias*) printf "%s\n" "$MOCK_SOURCE";;\n'
                '  *) exit 7;;\nesac\n')
            gh.chmod(0o755)
            output = root / "output"
            argv = root / "argv"
            env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                   "GITHUB_SHA": OWNER, "GITHUB_EVENT_NAME": event,
                   "ADMITTED_SHA": SHA, "ONLY_IF_NEW": only_if_new,
                   "GITHUB_OUTPUT": str(output), "MOCK_ARGS": str(argv),
                   "MOCK_CODE": str(code), "MOCK_OWNER": owner, "MOCK_SOURCE": source}
            result = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=5, check=False)
            return result, argv.read_text().splitlines(), (
                output.read_text().splitlines() if output.exists() else [])

    def test_automatic_pending_does_not_block_or_publish(self):
        for event, only_if_new in (("workflow_run", "false"), ("push", "false"),
                                   ("schedule", "false"), ("workflow_dispatch", "true")):
            with self.subTest(event=event):
                process, argv, output = self.run_gate(event=event, only_if_new=only_if_new)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(argv, ["scripts/chronicles_api_before_pages.py",
                                        "--ready-once", SHA])
                self.assertEqual(output, ["publish=false"])
                self.assertIn("API_PENDING_EVENT_OR_SCHEDULE", process.stdout)

    def test_automatic_ready_and_inconclusive_are_distinct(self):
        process, argv, output = self.run_gate(code=0)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(argv[1], "--ready-once")
        self.assertEqual(output, ["publish=true"])
        process, argv, output = self.run_gate(code=2)
        self.assertEqual(argv[1], "--ready-once")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(output, [])
        self.assertIn("API gate failed", process.stderr)

    def test_manual_staging_keeps_bounded_wait_and_failure(self):
        process, argv, output = self.run_gate(event="workflow_dispatch", code=0)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(argv, ["scripts/chronicles_api_before_pages.py", SHA])
        self.assertEqual(output, ["publish=true"])
        process, argv, output = self.run_gate(event="workflow_dispatch", code=3)
        self.assertEqual(argv, ["scripts/chronicles_api_before_pages.py", SHA])
        self.assertEqual(process.returncode, 1)
        self.assertEqual(output, [])

    def test_stale_source_or_owner_skip_before_any_pages_write(self):
        for kwargs in ({"source": "c" * 40, "code": 0},
                       {"owner": "c" * 40, "code": 0},
                       {"source": "c" * 40, "code": 3}):
            with self.subTest(kwargs=kwargs):
                process, _, output = self.run_gate(**kwargs)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(output, ["publish=false"])


if __name__ == "__main__":
    unittest.main()
