"""Offline Chronicle watch: transient failure suppression and issue lifecycle."""
from pathlib import Path
import datetime as dt
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_staging_watch as watch

SHA = "a" * 40
OLD = dt.datetime(2026, 10, 20, 10, 0, tzinfo=dt.timezone.utc)
NOW = OLD + dt.timedelta(hours=2)


def gh(path, token, *, method="GET", payload=None):
    if path.endswith("/commits/main"):
        return {"sha": SHA, "commit": {"committer": {"date": OLD.isoformat()}}}
    if "/actions/artifacts?" in path:
        return {"artifacts": []}
    return {"id": 123}


def url(url, token=""):
    return {"build": SHA}


class WatchTest(unittest.TestCase):
    def setUp(self):
        # Existing unit tests use a synthetic HTTP manifest; keep the public
        # HTML + asset probe deterministic without making network requests.
        mocked = patch.object(watch.pages, "probe_react_preview", return_value="ok")
        self.game_probe = mocked.start()
        self.addCleanup(mocked.stop)

    @patch.object(watch.ci, "inspect", return_value="pending")
    def test_game_entry_is_checked_even_while_source_ci_is_pending(self, _):
        self.game_probe.return_value = "js_content"
        bad = watch.failures("t", get=url, gh=gh, now=NOW)
        self.assertEqual(set(bad), {"pages-game"})
        self.game_probe.assert_called_once_with(
            path="/", assets=b"/assets/", manifest_path=None
        )

    @patch.object(watch.receipts, "public_api_revision_state", return_value="match")
    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_manifest_and_api_healthy_cannot_hide_broken_game_assets(self, _, __, ___):
        for state in ("html_missing", "js_reference", "js_mime",
                      "css_reference", "css_content", "http_404"):
            with self.subTest(state=state):
                self.game_probe.return_value = state
                self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)),
                                 {"pages-game"})
        for state in ("http_429", "http_500", "http_503", "http_522",
                      "unavailable", "http_error"):
            with self.subTest(state=state):
                self.game_probe.return_value = state
                self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)),
                                 {"pages-edge"})
        self.game_probe.return_value = "ok"
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})

    @patch.object(watch.ci, "inspect", return_value="pending")
    def test_watchdog_cannot_probe_a_different_pages_environment(self, _):
        with patch.object(watch.pages, "HOST", "chronicles.shadowops.dpdns.org"):
            with self.assertRaisesRegex(RuntimeError, "pinned staging origin"):
                watch.failures("t", get=url, gh=gh, now=NOW)
        self.game_probe.assert_not_called()

    @patch.object(watch.receipts, "public_api_revision_state", return_value="match")
    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_fully_green_but_missing_api_receipt_is_reported_after_grace(self, _, __):
        bad = watch.failures("t", get=url, gh=gh, now=NOW)
        self.assertEqual(set(bad), {"backend-lag"})

    @patch.object(watch.ci, "inspect", return_value="pending")
    def test_new_unfinished_source_does_not_cause_version_drift_alert(self, _):
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})

    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_recent_green_source_uses_grace_window(self, _):
        recent = OLD + dt.timedelta(minutes=20)
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=recent), {})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_live_api_sha_must_match_even_when_health_and_receipt_pass(self, _, __):
        with patch.object(watch.receipts, "public_api_revision_state", return_value="match") as live:
            self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})
            live.assert_called_once_with(SHA)
        with patch.object(watch.receipts, "public_api_revision_state", return_value="different"):
            self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"api-revision"})
        with patch.object(watch.receipts, "public_api_revision_state", return_value="unknown"):
            self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"api-revision"})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_bad_api_health_does_not_duplicate_revision_alarm(self, _, __):
        def degraded(address, token=""):
            if address.endswith("/health"):
                raise ValueError("HTTP health is degraded")
            return {"build": SHA}
        with patch.object(watch.receipts, "public_api_revision_state") as live:
            self.assertEqual(set(watch.failures("t", get=degraded, gh=gh, now=NOW)),
                             {"api-health"})
            live.assert_not_called()

    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_live_revision_is_not_probed_before_green_source_grace(self, _):
        with patch.object(watch.receipts, "public_api_revision_state") as live:
            self.assertEqual(watch.failures("t", get=url, gh=gh,
                                            now=OLD + dt.timedelta(minutes=20)), {})
            live.assert_not_called()

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch.ci, "inspect", return_value="ready")
    def test_unexpected_revision_state_fails_inconclusive_not_ok(self, _, __):
        with patch.object(watch.receipts, "public_api_revision_state", return_value="invalid"):
            with self.assertRaisesRegex(RuntimeError, "Unexpected public API revision state"):
                watch.failures("t", get=url, gh=gh, now=NOW)

    def test_watch_pages_failure_buckets_are_allowlisted_and_redacted(self):
        structural = ("html_missing", "js_reference", "css_content",
                      "js_mime", "http_403", "http_404")
        transient = ("http_429", "http_500", "http_503", "http_522",
                     "http_599", "http_error", "unavailable")
        for result in structural:
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-game")
        for result in transient:
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-edge")
        self.assertIsNone(watch.pages_failure_key("ok"))

    def test_structural_game_failure_alerts_after_two_samples(self):
        samples = [{"pages-game": "broken"}, {"pages-game": "broken"}]
        paused = []
        def probe(_token):
            return samples.pop(0)
        bad = watch.confirmed_failures("t", probe=probe, pause=paused.append)
        self.assertEqual(bad, {"pages-game": "broken"})
        self.assertEqual(paused, [90])
        self.assertEqual(samples, [])

    def test_one_off_cdn_failure_is_suppressed_by_second_sample(self):
        samples = [{"pages-edge": "edge"}, {}]
        paused = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append)
        self.assertEqual(bad, {})
        self.assertEqual(paused, [90])

    def test_cdn_failure_must_survive_three_samples_before_alert(self):
        for third, expected in [
            ({}, {}),
            ({"pages-edge": "still down"}, {"pages-edge": "still down"}),
            ({"pages-game": "HTML fallback"}, {"pages-game": "HTML fallback"}),
        ]:
            with self.subTest(third=third):
                samples = [{"pages-edge": "edge"}, {"pages-edge": "edge"}, third]
                paused = []
                bad = watch.confirmed_failures(
                    "t", probe=lambda _: samples.pop(0), pause=paused.append)
                self.assertEqual(bad, expected)
                self.assertEqual(paused, [90, 90])
                self.assertEqual(samples, [])

    def test_mixed_cdn_and_structural_failure_uses_third_sample(self):
        samples = [
            {"pages-edge": "network"}, {"pages-game": "bad MIME"},
            {"pages-edge": "still broken"},
        ]
        paused = []
        self.assertEqual(watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append),
            {"pages-edge": "still broken"})
        self.assertEqual(paused, [90, 90])

    def test_edge_recovery_does_not_hide_persistent_unrelated_health_failure(self):
        samples = [
            {"pages-edge": "transient", "api-health": "API down"},
            {"pages-edge": "transient", "api-health": "API down"},
            {},
        ]
        paused = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append)
        self.assertEqual(bad, {"api-health": "API down"})
        self.assertEqual(paused, [90, 90])

    def test_no_initial_failure_never_sleeps_or_rechecks(self):
        calls = []
        def probe(_token):
            calls.append("probe")
            return {}
        self.assertEqual(watch.confirmed_failures(
            "t", probe=probe,
            pause=lambda _: self.fail("Should not pause on healthy first sample")), {})
        self.assertEqual(calls, ["probe"])

    def test_one_issue_for_persistent_failures_and_auto_close_on_recovery(self):
        open_issues = []
        writes = []
        def api(path, token, *, method="GET", payload=None):
            if path.endswith("/issues?state=open&per_page=100"):
                return open_issues
            writes.append((method, path, payload))
            if method == "POST":
                open_issues.append({"number": 42, "title": watch.TITLE})
            elif method == "PATCH":
                open_issues.clear()
            return {"number": 42}

        fault = {"api-health": "API unavailable"}
        self.assertEqual(watch.manage_issue("t", fault, gh=api),
                         "CHRONICLES_STAGING_WATCH_ISSUE_OPENED")
        self.assertEqual(watch.manage_issue("t", fault, gh=api),
                         "CHRONICLES_STAGING_WATCH_ALREADY_OPEN")
        self.assertEqual(len([x for x in writes if x[0] == "POST"]), 1)
        self.assertEqual(watch.manage_issue("t", {}, gh=api),
                         "CHRONICLES_STAGING_WATCH_RECOVERED")
        self.assertEqual(watch.manage_issue("t", {}, gh=api),
                         "CHRONICLES_STAGING_WATCH_OK")

    def test_mixed_signal_intersection_filters_transient_failure(self):
        first = {"api-health": "down", "frontend-lag": "lag"}
        second = {"api-health": "down", "pages-manifest": "temporarily broken"}
        persistent = {k: second[k] for k in first.keys() & second.keys()}
        self.assertEqual(persistent, {"api-health": "down"})


if __name__ == "__main__":
    unittest.main()
