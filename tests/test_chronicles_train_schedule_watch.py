"""An independent read-only check that the 08:00 Madrid train ran today."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_train_schedule_watch as watch

MADRID = ZoneInfo("Europe/Madrid")


def scheduled(created, **changes):
    data = {
        "id": 12345,
        "created_at": created,
        "event": "schedule",
        "path": watch.WORKFLOW,
        "head_branch": "main",
        "repository": {"full_name": watch.REPO},
        "status": "in_progress",
    }
    data.update(changes)
    return data


class Response:
    def __init__(self, url, data, status=200):
        self.url, self.data, self.status = url, data, status
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def geturl(self):
        return self.url
    def read(self, size):
        return self.data[:size]


class TrainScheduleWatchTests(unittest.TestCase):
    def test_madrid_local_eight_summer_and_winter(self):
        summer = datetime(2026, 10, 22, 9, 15, tzinfo=MADRID)
        winter = datetime(2026, 10, 26, 9, 15, tzinfo=MADRID)
        self.assertEqual(watch.scheduled_today(
            [scheduled("2026-10-22T06:00:16Z")], summer), 12345)
        self.assertEqual(watch.scheduled_today(
            [scheduled("2026-10-26T07:00:16Z")], winter), 12345)
        self.assertIsNone(watch.scheduled_today(
            [scheduled("2026-10-22T06:00:16Z")], winter))
        # Backward-compatible existence helper sees queued jobs; the
        # daily watchdog separately requires completed success.
        self.assertEqual(watch.scheduled_today(
            [scheduled("2026-10-22T07:00:16Z", status="queued")], summer), 12345)

    def test_daily_job_requires_completed_green_train_not_only_a_run_id(self):
        now = datetime(2026, 10, 22, 9, 15, tzinfo=MADRID)
        base = scheduled("2026-10-22T06:00:16Z", status="completed",
                         conclusion="success")
        self.assertEqual(watch.completed_train_today([base], now), 12345)
        for state, conclusion, marker in (
            ("queued", None, "INCOMPLETE"),
            ("in_progress", None, "INCOMPLETE"),
            ("waiting", None, "INCOMPLETE"),
            ("completed", "failure", "FAILED"),
            ("completed", "cancelled", "FAILED"),
            ("completed", "skipped", "FAILED"),
            ("completed", None, "FAILED"),
        ):
            with self.subTest(state=state, conclusion=conclusion):
                with self.assertRaisesRegex(watch.ScheduleError, marker):
                    watch.completed_train_today(
                        [scheduled("2026-10-22T06:00:16Z",
                                   status=state, conclusion=conclusion)], now)
        with self.assertRaisesRegex(watch.ScheduleError, "NOT_OBSERVED"):
            watch.completed_train_today([], now)

    def test_latest_scheduled_run_takes_precedence_over_earlier_success(self):
        now = datetime(2026, 10, 22, 9, 15, tzinfo=MADRID)
        earlier = scheduled("2026-10-22T06:00:00Z", id=23,
                            status="completed", conclusion="success")
        later = scheduled("2026-10-22T06:02:00Z", id=24,
                          status="completed", conclusion="failure")
        with self.assertRaisesRegex(watch.ScheduleError, "FAILED"):
            watch.completed_train_today([earlier, later], now)
        self.assertEqual(watch.scheduled_today([later, earlier], now), 24)
        later["conclusion"] = "success"
        self.assertEqual(watch.completed_train_today([earlier, later], now), 24)
        # Source labels alone aren't enough: reject scheduled events from
        # other repositories even when the claimed conclusion is success.
        later["repository"] = {"full_name": "another/infra"}
        self.assertEqual(watch.completed_train_today([earlier, later], now), 23)

    def test_missing_old_early_future_or_forged_schedule_fails_closed(self):
        now = datetime(2026, 10, 22, 9, 15, tzinfo=MADRID)
        for case in (
            scheduled("2026-10-21T06:00:00Z"),
            scheduled("2026-10-22T04:00:00Z"),
            scheduled("2026-10-22T08:00:00Z"),
            scheduled("2026-10-22T06:00:00Z", event="workflow_dispatch"),
            scheduled("2026-10-22T06:00:00Z", path=".github/workflows/other.yml"),
            scheduled("2026-10-22T06:00:00Z", head_branch="feature"),
            scheduled("2026-10-22T06:00:00Z",
                      repository={"full_name": "untrusted/infra"}),
            scheduled("2026-10-22T06:00:00Z", id=True),
            scheduled("2026-10-22T06:00:00Z", id=0),
            scheduled("garbled"),
            scheduled("2026-10-22T06:00:00"),
            {},
            None,
        ):
            with self.subTest(case=case):
                self.assertIsNone(watch.scheduled_today([case], now))
        with self.assertRaises(watch.ScheduleError):
            watch.scheduled_today([], datetime(2026, 10, 22, 9, 15))

    def test_completed_workflow_cannot_hide_skipped_or_failed_promotion_job(self):
        def job(**overrides):
            base = {
                "name": watch.TRAIN_JOB,
                "status": "completed",
                "conclusion": "success",
                "steps": [{"name": watch.TRAIN_STEP, "status": "completed",
                           "conclusion": "success"}],
            }
            base.update(overrides)
            return base
        self.assertTrue(watch.train_job_succeeded([job()]))
        for invalid in (
            [], [job(status="queued")], [job(conclusion="skipped")],
            [job(conclusion="failure")], [job(steps=[])],
            [job(steps=[{"name": watch.TRAIN_STEP, "status": "completed",
                          "conclusion": "skipped"}])],
            [job(name="Release train offline contracts")],
            [job(), job()],
            [None, {"name": watch.TRAIN_JOB}],
        ):
            with self.subTest(jobs=invalid):
                self.assertFalse(watch.train_job_succeeded(invalid))

    def test_child_jobs_are_read_from_fixed_api_without_mutations(self):
        run_id = 123456
        url = (f"https://api.github.com/repos/{watch.REPO}/actions/runs/"
               f"{run_id}/jobs?per_page=100")
        jobs = [{"name": watch.TRAIN_JOB, "status": "completed",
                 "conclusion": "success", "steps": []}]
        payload = json.dumps({"total_count": 1, "jobs": jobs}).encode()
        observed = []
        def opener(req, timeout):
            observed.append((req, timeout))
            return Response(url, payload)
        self.assertEqual(watch.fetch_train_jobs(run_id, "read-token", opener=opener), jobs)
        request, timeout = observed[0]
        self.assertEqual(timeout, 15)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, url)
        self.assertEqual(request.get_header("Authorization"), "Bearer read-token")
        self.assertNotIn("Cookie", request.headers)
        for invalid in (True, -1, 0, "123456"):
            with self.subTest(run_id=invalid), self.assertRaises(watch.ScheduleError):
                watch.fetch_train_jobs(invalid, "read-token", opener=opener)
        for data, redirect in (
            (payload, "https://other.example/jobs"),
            (b"{}" , url),
            (b"{bad", url),
            (json.dumps({"total_count": 101, "jobs": jobs}).encode(), url),
            (b" " * 512001, url),
        ):
            with self.subTest(data_len=len(data), redirect=redirect):
                with self.assertRaises((watch.ScheduleError, ValueError)):
                    watch.fetch_train_jobs(
                        run_id, "read-token",
                        opener=lambda *_args, **_kwargs: Response(redirect, data))

    def test_main_rejects_green_workflow_with_skipped_train_job(self):
        env = {"GITHUB_REPOSITORY": watch.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GH_TOKEN": "private-test-token"}
        with patch.dict(os.environ, env, clear=True):
            with patch.object(watch, "fetch_runs", return_value=[{}]), \\
                 patch.object(watch, "completed_train_today", return_value=42), \\
                 patch.object(watch, "fetch_train_jobs", return_value=[
                    {"name": watch.TRAIN_JOB, "status": "completed",
                     "conclusion": "skipped", "steps": []}]):
                self.assertEqual(watch.main(), 1)
            with patch.object(watch, "fetch_runs", return_value=[{}]), \\
                 patch.object(watch, "completed_train_today", return_value=42), \\
                 patch.object(watch, "fetch_train_jobs", return_value=[
                    {"name": watch.TRAIN_JOB, "status": "completed",
                     "conclusion": "success",
                     "steps": [{"name": watch.TRAIN_STEP, "status": "completed",
                                "conclusion": "success"}]}]):
                self.assertEqual(watch.main(), 0)

    def test_request_is_exact_origin_read_only_and_bounded(self):
        record = scheduled("2026-10-22T06:02:00Z")
        payload = json.dumps({"workflow_runs": [record]}).encode()
        calls = []
        def opener(request, timeout):
            calls.append((request, timeout))
            return Response(watch.URL, payload)
        self.assertEqual(watch.fetch_runs("fake-read-token", opener=opener), [record])
        request, timeout = calls[0]
        self.assertEqual(timeout, 15)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, watch.URL)
        self.assertEqual(request.get_header("Authorization"), "Bearer fake-read-token")
        self.assertNotIn("Cookie", request.headers)
        self.assertEqual(watch.URL.count("event=schedule"), 1)
        with self.assertRaises(watch.ScheduleError):
            watch.fetch_runs("", opener=opener)

        for bad in (
            Response("https://evil.example/actions/runs", payload),
            Response(watch.URL, payload, status=503),
            Response(watch.URL, b"{broken"),
            Response(watch.URL, b"{}"),
            Response(watch.URL, json.dumps({"workflow_runs": [{}] * 11}).encode()),
            Response(watch.URL, b" " * 256001),
        ):
            with self.subTest(url=bad.url, size=len(bad.data)):
                def open_bad(*_args, **_kwargs):
                    return bad
                with self.assertRaises((watch.ScheduleError, ValueError)):
                    watch.fetch_runs("fake-read-token", opener=open_bad)

    def test_schedule_watcher_is_separate_read_only_job(self):
        src = (Path(__file__).resolve().parents[1] /
               ".github/workflows/chronicles-production-audit.yml").read_text()
        self.assertIn("  schedule_watch:\n", src)
        self.assertIn("github.event_name == 'schedule'", src)
        self.assertIn("cron: '15 9 * * *'", src)
        self.assertIn("timezone: Europe/Madrid", src)
        self.assertIn("actions: read", src)
        self.assertNotIn("actions: write", src)
        self.assertNotIn("issues: write", src)
        self.assertIn("scripts/chronicles_train_schedule_watch.py", src)
        self.assertIn("test_chronicles_train_schedule_watch.py", src)

    def test_main_fails_closed_without_leaking_token(self):
        context = {"GITHUB_REPOSITORY": watch.REPO,
                   "GITHUB_REF": "refs/heads/main",
                   "GITHUB_EVENT_NAME": "schedule",
                   "GH_TOKEN": "test-private-token"}
        with patch.dict(os.environ, context, clear=True):
            with patch.object(watch, "fetch_runs", return_value=[]) as fetch:
                self.assertEqual(watch.main(), 1)
                fetch.assert_called_once_with("test-private-token")
        with patch.dict(os.environ, {**context, "GITHUB_EVENT_NAME": "push"}, clear=True):
            with patch.object(watch, "fetch_runs") as fetch:
                self.assertEqual(watch.main(), 1)
                fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
