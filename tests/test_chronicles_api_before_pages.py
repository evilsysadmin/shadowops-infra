"""Offline API-to-Pages gate, including forged/pending/failed receipts."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_api_before_pages as gate

SHA = "a" * 40
TOKEN = "fake-read-token"


def receipt(run_id=123, *, expired=False, branch="main"):
    return {"name": "chronicles-api-staging-" + SHA, "expired": expired,
            "workflow_run": {"id": run_id, "head_branch": branch}}


def run(**overrides):
    data = {"id": 123, "status": "completed", "conclusion": "success",
            "head_branch": "main", "path": gate.API_WORKFLOW,
            "repository": {"full_name": gate.INFRA}, "event": "workflow_dispatch"}
    data.update(overrides)
    return data


class ApiBeforePages(unittest.TestCase):
    def test_only_trusted_successful_api_receipt_admits(self):
        self.assertTrue(gate.evidence_ok(SHA, {"artifacts": [receipt()]}, lambda _: run()))
        for invalid in (
            run(conclusion="failure"), run(status="in_progress", conclusion=None),
            run(path=".github/workflows/chronicles-pages-release.yml"),
            run(repository={"full_name": gate.SOURCE}),
            run(head_branch="feature"), run(event="pull_request"),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.evidence_ok(SHA, {"artifacts": [receipt()]}, lambda _: invalid))
        for invalid in (receipt(expired=True), receipt(branch="feature"),
                        {**receipt(), "name": "chronicles-api-staging-" + "b" * 40}):
            self.assertFalse(gate.evidence_ok(SHA, {"artifacts": [invalid]}, lambda _: run()))
        with self.assertRaises(gate.GateError):
            gate.evidence_ok(SHA, {}, lambda _: run())

    def test_one_shot_receipt_probe_reuses_trusted_run_validation(self):
        calls = []
        def get(path, token):
            calls.append((path, token))
            return {"artifacts": [receipt()]} if "/actions/artifacts?" in path else run()
        self.assertTrue(gate.api_receipt_available(SHA, TOKEN, get=get))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(token == TOKEN for _, token in calls))
        self.assertTrue(any("name=chronicles-api-staging-" + SHA in path
                            for path, _ in calls))
        self.assertFalse(gate.api_receipt_available(
            SHA, TOKEN, get=lambda path, _: {"artifacts": []}))
        def failed(path, token):
            return {"artifacts": [receipt()]} if "/actions/artifacts?" in path else run(conclusion="failure")
        self.assertFalse(gate.api_receipt_available(SHA, TOKEN, get=failed))
        with self.assertRaises(gate.GateError):
            gate.api_receipt_available("invalid", TOKEN, get=get)
        with self.assertRaises(gate.GateError):
            gate.api_receipt_available(SHA, "", get=get)
        with self.assertRaisesRegex(gate.GateError, "Missing deployment artifacts"):
            gate.api_receipt_available(SHA, TOKEN, get=lambda path, _: {})

    def test_api_workflow_reuses_receipt_only_gate_not_artifact_count(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-api-staging.yml").read_text()
        self.assertIn("chronicles_api_before_pages.py --receipt-only", workflow)
        self.assertIn("CHRONICLES_API_RECEIPT_CHECK_INCONCLUSIVE", workflow)
        self.assertIn("receipt_status != 1", workflow)
        self.assertNotIn("count=\"$(gh api -X GET", workflow)

    def test_live_health_probe_retries_transient_and_fails_closed(self):
        calls = []
        def probe(path):
            calls.append(path)
            return len(calls) != 1
        self.assertTrue(gate.public_api_healthy(probe=probe, sleep=lambda _: None))
        self.assertEqual(calls, ["health", "health", "ready"])

        calls = []
        self.assertFalse(gate.public_api_healthy(
            probe=lambda path: calls.append(path) or False,
            sleep=lambda _: None))
        self.assertEqual(calls, ["health", "health"])

    def test_receipt_only_cli_distinguishes_missing_unhealthy_and_verified(self):
        with patch.object(gate.sys, "argv", ["gate", "--receipt-only", SHA]), \
             patch.dict(gate.os.environ, {"GH_TOKEN": TOKEN}):
            with patch.object(gate, "api_receipt_available", return_value=False), \
                 patch.object(gate, "public_api_healthy") as live:
                self.assertEqual(gate.main(), 1)
                live.assert_not_called()
            with patch.object(gate, "api_receipt_available", return_value=True), \
                 patch.object(gate, "public_api_healthy", return_value=False):
                self.assertEqual(gate.main(), 2)
            with patch.object(gate, "api_receipt_available", return_value=True), \
                 patch.object(gate, "public_api_healthy", return_value=True):
                self.assertEqual(gate.main(), 0)

    def test_api_health_probe_uses_both_public_paths_and_https(self):
        with patch.object(gate.urllib.request, "urlopen") as opener:
            opener.return_value.__enter__.return_value.status = 200
            self.assertTrue(gate.probe_public("health"))
            request = opener.call_args.args[0]
            self.assertEqual(request.full_url, gate.API_ORIGIN + "/health")
            self.assertTrue(request.full_url.startswith("https://"))
            opener.return_value.__enter__.return_value.status = 503
            self.assertFalse(gate.probe_public("ready"))
        with patch.object(gate.urllib.request, "urlopen", side_effect=TimeoutError):
            self.assertFalse(gate.probe_public("ready"))

    def test_waits_for_receipt_and_rechecks_source_main(self):
        calls = []
        counter = {"n": 0}
        def get(path, token):
            calls.append(path)
            if path.endswith("/commits/main"):
                return {"sha": SHA}
            if "/actions/artifacts?" in path:
                counter["n"] += 1
                return {"artifacts": [] if counter["n"] == 1 else [receipt()]}
            return run()
        gate.wait_for_api(SHA, TOKEN, attempts=3, sleep=lambda _: None,
                          get=get, healthy=lambda: True)
        self.assertEqual(counter["n"], 2)
        self.assertEqual(sum(p.endswith("/commits/main") for p in calls), 2)

    def test_pages_cannot_mutate_when_trusted_api_receipt_is_not_live(self):
        calls = []
        def get(path, token):
            calls.append(path)
            if path.endswith("/commits/main"):
                return {"sha": SHA}
            if "/actions/artifacts?" in path:
                return {"artifacts": [receipt()]}
            return run()
        with self.assertRaisesRegex(gate.GateError, "PUBLIC_HEALTH_UNAVAILABLE"):
            gate.wait_for_api(SHA, TOKEN, attempts=4, sleep=lambda _: None,
                              get=get, healthy=lambda: False)
        self.assertEqual(sum("/artifacts?" in path for path in calls), 1)
        self.assertEqual(sum(path.endswith("/commits/main") for path in calls), 1)

    def test_cannot_publish_stale_source_or_missing_api(self):
        def stale(path, token):
            return {"sha": "b" * 40}
        with self.assertRaisesRegex(gate.GateError, "STALE_SOURCE"):
            gate.wait_for_api(SHA, TOKEN, attempts=1, get=stale)
        def missing(path, token):
            return {"sha": SHA} if path.endswith("/commits/main") else {"artifacts": []}
        with self.assertRaisesRegex(gate.GateError, "RECEIPT_TIMEOUT"):
            gate.wait_for_api(SHA, TOKEN, attempts=2, sleep=lambda _: None, get=missing)


if __name__ == "__main__":
    unittest.main()
