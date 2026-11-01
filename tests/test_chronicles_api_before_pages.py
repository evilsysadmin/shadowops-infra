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
        self.assertIn("run: bash scripts/chronicles_api_candidate.sh", workflow)
        selection = (Path(__file__).resolve().parents[1] /
                     "scripts/chronicles_api_candidate.sh").read_text(encoding="utf-8")
        self.assertIn("chronicles_api_before_pages.py --receipt-only", selection)
        self.assertIn("CHRONICLES_API_RECEIPT_CHECK_INCONCLUSIVE", selection)
        self.assertIn("receipt_status != 1", selection)
        self.assertNotIn("count=\"$(gh api -X GET", selection)

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
                 patch.object(gate, "public_api_healthy", return_value=True), \
                 patch.object(gate, "public_api_revision_state", return_value="match"):
                self.assertEqual(gate.main(), 0)
            with patch.object(gate, "api_receipt_available", return_value=True), \
                 patch.object(gate, "public_api_healthy", return_value=True), \
                 patch.object(gate, "public_api_revision_state", return_value="different"):
                self.assertEqual(gate.main(), 1)
            with patch.object(gate, "api_receipt_available", return_value=True), \
                 patch.object(gate, "public_api_healthy", return_value=True), \
                 patch.object(gate, "public_api_revision_state", return_value="unknown"):
                self.assertEqual(gate.main(), 2)

    def test_public_sha_only_cli_is_read_only_and_fail_closed(self):
        with patch.object(gate.sys, "argv", ["gate", "--public-sha-only", SHA]), \
             patch.dict(gate.os.environ, {}, clear=True):
            for state, expected in (("match", 0), ("different", 1), ("unknown", 2)):
                with self.subTest(state=state), \
                     patch.object(gate, "public_api_revision_state", return_value=state), \
                     patch.object(gate, "api_receipt_available") as artifacts:
                    self.assertEqual(gate.main(), expected)
                    artifacts.assert_not_called()

    def test_api_health_probe_uses_both_public_paths_and_https(self):
        with patch.object(gate.urllib.request, "urlopen") as opener:
            opener.return_value.__enter__.return_value.status = 200
            opener.return_value.__enter__.return_value.geturl.return_value = gate.API_ORIGIN + "/health"
            self.assertTrue(gate.probe_public("health"))
            request = opener.call_args.args[0]
            self.assertEqual(request.full_url, gate.API_ORIGIN + "/health")
            self.assertTrue(request.full_url.startswith("https://"))
            opener.return_value.__enter__.return_value.status = 503
            opener.return_value.__enter__.return_value.geturl.return_value = gate.API_ORIGIN + "/ready"
            self.assertFalse(gate.probe_public("ready"))
            opener.return_value.__enter__.return_value.status = 200
            opener.return_value.__enter__.return_value.geturl.return_value = "https://evil.example/ready"
            self.assertFalse(gate.probe_public("ready"))
            opener.return_value.__enter__.return_value.geturl.return_value = gate.API_ORIGIN + "/health"
            self.assertFalse(gate.probe_public("ready"))
            self.assertFalse(gate.probe_public("../users"))
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
                          get=get, healthy=lambda: True, revision=lambda _: "match")
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

    def test_api_release_proves_exact_public_source_revision(self):
        sha = SHA
        def response(body, status=200, final_url=None):
            class Fake:
                def __enter__(self):
                    return self
                def __exit__(self, *_):
                    return False
                def geturl(self):
                    return final_url or gate.API_ORIGIN + "/release"
                def read(self, limit):
                    self_read_limit.append(limit)
                    return body[:limit]
            result = Fake()
            result.status = status
            return result
        self_read_limit = []
        def open_ok(request, timeout):
            self.assertEqual(timeout, 10)
            self.assertTrue(request.full_url.startswith(gate.API_ORIGIN + "/release?sha_check="))
            return response(('{"release":"v1","build":"' + sha + '"}').encode())
        self.assertEqual(gate.read_public_build(opener=open_ok), sha)
        self.assertEqual(self_read_limit, [4097])
        self.assertEqual(gate.public_api_revision_state(sha, read=lambda: sha), "match")
        self.assertEqual(gate.public_api_revision_state(sha, read=lambda: "b" * 40), "different")
        self.assertEqual(gate.public_api_revision_state(sha, read=lambda: None), "unknown")
        self.assertIsNone(gate.read_public_build(opener=lambda *_args, **_kwargs: response(b'{"release":"v1"}')))
        self.assertIsNone(gate.read_public_build(opener=lambda *_args, **_kwargs: response(b'{"build":"bad"}')))
        self.assertIsNone(gate.read_public_build(opener=lambda *_args, **_kwargs: response(b'not-json')))
        self.assertIsNone(gate.read_public_build(opener=lambda *_args, **_kwargs: response(b'{}', 503)))
        self.assertIsNone(gate.read_public_build(
            opener=lambda *_args, **_kwargs: response(
                ('{"build":"' + SHA + '"}').encode(), final_url="https://evil.example/release")))
        self.assertIsNone(gate.read_public_build(
            opener=lambda *_args, **_kwargs: response(
                ('{"build":"' + SHA + '"}').encode(), final_url=gate.API_ORIGIN + "/health")))
        self.assertIsNone(gate.read_public_build(
            opener=lambda *_args, **_kwargs: response(b" " * 4097)))
        self.assertIsNone(gate.read_public_build(
            opener=lambda *_args, **_kwargs: response(
                ('{"build":"' + SHA + '"}').encode(), final_url="http://chronicles-api-staging.shadowops.dpdns.org/api/release")))

        def outage(*_args, **_kwargs):
            raise TimeoutError()
        self.assertIsNone(gate.read_public_build(opener=outage))
        with self.assertRaises(gate.GateError):
            gate.public_api_revision_state("not-a-sha")

    def test_pages_refuses_trusted_receipt_when_public_api_revision_differs(self):
        def get(path, _token):
            if path.endswith("/commits/main"):
                return {"sha": SHA}
            return {"artifacts": [receipt()]} if "/actions/artifacts?" in path else run()
        with self.assertRaisesRegex(gate.GateError, "PUBLIC_SOURCE_MISMATCH"):
            gate.wait_for_api(SHA, TOKEN, attempts=1, get=get,
                              healthy=lambda: True, revision=lambda _: "different")
        with self.assertRaisesRegex(gate.GateError, "PUBLIC_SOURCE_INCONCLUSIVE"):
            gate.wait_for_api(SHA, TOKEN, attempts=1, get=get,
                              healthy=lambda: True, revision=lambda _: "unknown")
        gate.wait_for_api(SHA, TOKEN, attempts=1, get=get,
                          healthy=lambda: True, revision=lambda _: "match")

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
