"""Offline source CI workflow identity and verdict tests."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_source_ci as ci

SHA = "a" * 40
TOKEN = "test-read-token"


def run(workflow_id, *, state="completed", conclusion="success", **changes):
    name, path = ci.REQUIRED[workflow_id]
    out = {
        "id": workflow_id,
        "workflow_id": workflow_id,
        "name": name,
        "path": path,
        "head_sha": SHA,
        "event": "push",
        "head_branch": "main",
        "repository": {"full_name": ci.SOURCE},
        "status": state,
        "conclusion": conclusion,
    }
    out.update(changes)
    return out


def read(rows):
    return lambda sha, token: {"total_count": len(rows), "workflow_runs": rows}


class VerifyExactSourceCI(unittest.TestCase):
    def setUp(self):
        self.rows = [run(i) for i in ci.REQUIRED]

    def test_three_successful_source_main_push_workflows_admit(self):
        self.assertEqual(ci.inspect(SHA, TOKEN, read(self.rows)), "ready")

    def test_missing_or_in_progress_workflow_is_pending(self):
        self.assertEqual(ci.inspect(SHA, TOKEN, read(self.rows[:-1])), "pending")
        rows = list(self.rows)
        rows[1] = run(386812503, state="in_progress", conclusion=None)
        self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "pending")

    def test_failure_or_cancellation_blocks_release(self):
        for failure in ("failure", "cancelled", "timed_out", "skipped"):
            with self.subTest(failure=failure):
                rows = list(self.rows)
                rows[0] = run(385763056, conclusion=failure)
                self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "blocked")

    def test_source_identity_spoof_and_fork_fail_closed(self):
        for change in (
            {"head_sha": "b" * 40}, {"event": "pull_request"},
            {"head_branch": "develop"}, {"path": ".github/workflows/other.yml"},
            {"repository": {"full_name": "attacker/repo"}}, {"name": "Fake CI"},
        ):
            with self.subTest(change=change):
                rows = list(self.rows)
                rows[1] = run(386812503, **change)
                with self.assertRaises(ci.AdmissionError):
                    ci.inspect(SHA, TOKEN, read(rows))

    def test_newer_failed_run_cannot_be_masked_by_older_success(self):
        rows = list(self.rows) + [run(386812503, id=999999999, conclusion="failure")]
        self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "blocked")

    def test_bad_sha_or_token_and_truncated_response_rejected(self):
        with self.assertRaises(ci.AdmissionError):
            ci.inspect("main", TOKEN, read(self.rows))
        with self.assertRaises(ci.AdmissionError):
            ci.inspect(SHA, "", read(self.rows))
        with self.assertRaises(ci.AdmissionError):
            ci.inspect(SHA, TOKEN, lambda sha, token: {"total_count": 101, "workflow_runs": self.rows})


if __name__ == "__main__":
    unittest.main()
