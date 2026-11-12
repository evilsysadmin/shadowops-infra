import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import snooker_staging_wake as wake
from snooker_source_admission import AdmissionError

SHA = "a" * 40
OTHER = "b" * 40


class Reader:
    def __init__(self, values=None):
        self.values = list(values or [SHA])
        self.calls = 0

    def get(self, path):
        assert path == "/repos/evilsysadmin/snooker-of-matthias/commits/main"
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        return {"sha": value}


class NoWrites:
    def write(self, *_args):
        raise AssertionError("Watchdog is never allowed to write Cloudflare")


class WatchdogTests(unittest.TestCase):
    def test_current_deployment_needs_no_source_artifact_and_never_dispatches(self):
        reader = Reader()
        checked = []
        def plan(cloud, sha):
            checked.append(sha)
            return {"publish": False, "reason": "current"}
        result = wake.decide(reader, NoWrites(), plan=plan,
            admit=lambda *_: self.fail("Current release cannot require an expired ZIP"))
        self.assertIsNone(result)
        self.assertEqual(checked, [SHA])
        self.assertEqual(reader.calls, 1)

    def test_stale_private_release_dispatches_only_after_exact_green_main(self):
        reader = Reader()
        admitted = []
        def admit(_reader, sha):
            admitted.append(sha)
            return {"source_sha": sha, "artifact_id": 123, "artifact_digest": "sha256:" + "c"*64}
        result = wake.decide(reader, NoWrites(),
            plan=lambda *_: {"publish": True, "reason": "source-mismatch"},
            admit=admit)
        self.assertEqual(result, SHA)
        self.assertEqual(admitted, [SHA])
        self.assertEqual(reader.calls, 2)

    def test_red_ci_or_missing_archive_must_fail_closed_before_dispatch(self):
        with self.assertRaises(AdmissionError):
            wake.decide(Reader(), NoWrites(),
                plan=lambda *_: {"publish": True, "reason": "source-mismatch"},
                admit=lambda *_: (_ for _ in ()).throw(
                    AdmissionError("No green exact-main source CI push run")))

    def test_moved_main_and_unverified_proof_block_dispatch(self):
        with self.assertRaises(wake.WakeBlocked):
            wake.decide(Reader([SHA, OTHER]), NoWrites(),
                plan=lambda *_: {"publish": True, "reason": "source-mismatch"},
                admit=lambda _, sha: {"source_sha": sha})
        for proof in (None, {"source_sha": OTHER}, {"run_id": 10}):
            with self.subTest(proof=proof), self.assertRaises(wake.WakeBlocked):
                wake.decide(Reader(), NoWrites(),
                    plan=lambda *_: {"publish": True, "reason": "source-mismatch"},
                    admit=lambda *_: proof)

    def test_unsafe_or_unknown_release_plan_never_dispatches(self):
        for plan in ({"publish": True, "reason": "identity-down"},
                     {"publish": False, "reason": "source-mismatch"}, {},
                     None):
            with self.subTest(plan=plan), self.assertRaises(wake.WakeBlocked):
                wake.decide(Reader(), NoWrites(), plan=lambda *_: plan,
                    admit=lambda *_: self.fail("Unsafe plan must never admit"))

    def test_actions_context_is_exact_protected_main_and_workflow(self):
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": wake.REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_WORKFLOW_REF": wake.REPO + "/.github/workflows/" + wake.WORKFLOW + "@refs/heads/main",
            "GITHUB_SHA": SHA,
            "GITHUB_OUTPUT": "/tmp/actions-output",
        }
        self.assertTrue(wake.valid_context(env))
        for key, wrong in [
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_REPOSITORY", "evilsysadmin/other"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_WORKFLOW_REF", "evilsysadmin/shadowops-infra/.github/workflows/evil.yml@refs/heads/main"),
            ("GITHUB_SHA", "not-a-sha"),
            ("GITHUB_OUTPUT", ""),
        ]:
            altered = {**env, key: wrong}
            with self.subTest(key=key):
                self.assertFalse(wake.valid_context(altered))

    def test_output_records_only_bounded_dispatch_and_noop(self):
        with TemporaryDirectory() as directory:
            output = str(Path(directory) / "output")
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": wake.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "schedule",
                "GITHUB_WORKFLOW_REF": wake.REPO + "/.github/workflows/" + wake.WORKFLOW + "@refs/heads/main",
                "GITHUB_SHA": SHA,
                "GITHUB_OUTPUT": output,
                "GH_TOKEN": "not-logged",
            }
            with patch.object(wake, "Client", return_value=NoWrites()), \
                 patch.object(wake.admission, "GithubReader", return_value=Reader()), \
                 patch.object(wake, "decide", return_value=None):
                self.assertEqual(wake.main(env), 0)
            self.assertEqual(Path(output).read_text(), "dispatch=false\n")
            Path(output).write_text("")
            with patch.object(wake, "Client", return_value=NoWrites()), \
                 patch.object(wake.admission, "GithubReader", return_value=Reader()), \
                 patch.object(wake, "decide", return_value=SHA):
                self.assertEqual(wake.main(env), 0)
            self.assertEqual(Path(output).read_text(), "dispatch=true\nsource_sha=" + SHA + "\n")

    def test_workflow_never_uploads_and_only_dispatches_protected_main(self):
        yml = (ROOT / ".github/workflows/snooker-staging-watchdog.yml").read_text()
        self.assertIn("cron: '07,37 * * * *'", yml)
        self.assertIn("environment:\n      name: staging", yml)
        self.assertIn("actions: write", yml)
        self.assertIn("steps.decide.outputs.dispatch == 'true'", yml)
        self.assertIn("snooker-pages-release.yml --repo evilsysadmin/shadowops-infra --ref main", yml)
        self.assertIn("gh api repos/evilsysadmin/snooker-of-matthias/commits/main", yml)
        self.assertNotIn("wrangler pages deploy", yml)
        self.assertNotIn("snooker_pages_provision.py project", yml)


if __name__ == "__main__":
    unittest.main()
