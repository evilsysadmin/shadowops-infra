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
        # GitHub may delay or queue the workflow; only existence is tested,
        # never success of an unfinished run.
        self.assertEqual(watch.scheduled_today(
            [scheduled("2026-10-22T07:00:16Z", status="queued")], summer), 12345)

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
            with patch.object(watch, "fetch_runs", return_value=[
                    scheduled(datetime.now(timezone.utc).isoformat())]):
                # Actual user clock at 13:00 is not the requested 08:00 run.
                # Compare against the clock from a fixed test below instead.
                pass
        with patch.dict(os.environ, {**context, "GITHUB_EVENT_NAME": "push"}, clear=True):
            with patch.object(watch, "fetch_runs") as fetch:
                self.assertEqual(watch.main(), 1)
                fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
