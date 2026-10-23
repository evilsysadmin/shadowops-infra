"""Trust only a successful Pages receipt whose SHA still matches live HTTPS."""
from pathlib import Path
import io
import json
import sys
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages_verified_receipt as gate

SHA = "a" * 40
TOKEN = "test-token"


def receipt(*, sha=SHA, run_id=123, expired=False, branch="main"):
    return {"name": "chronicles-pages-staging-" + sha,
            "expired": expired,
            "workflow_run": {"id": run_id, "head_branch": branch}}


def run(**overrides):
    data = {"id": 123, "status": "completed", "conclusion": "success",
            "path": gate.PAGES_WORKFLOW, "head_branch": "main",
            "repository": {"full_name": gate.INFRA}, "event": "schedule"}
    data.update(overrides)
    return data


class PagesVerifiedReceipt(unittest.TestCase):
    def test_only_successful_matching_workflow_receipt_is_trusted(self):
        listing = {"artifacts": [receipt()]}
        self.assertTrue(gate.receipt_ok(SHA, listing, lambda _: run()))
        for invalid in (
            run(conclusion="failure"), run(status="in_progress"),
            run(path=".github/workflows/chronicles-api-staging.yml"),
            run(head_branch="feature"), run(repository={"full_name": "fork/repo"}),
            run(event="pull_request"), run(id=999),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.receipt_ok(SHA, listing, lambda _: invalid))
        for invalid in (receipt(expired=True), receipt(branch="feature"),
                        receipt(sha="b" * 40), receipt(run_id=0)):
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.receipt_ok(SHA, {"artifacts": [invalid]}, lambda _: run()))
        with self.assertRaises(gate.GateError):
            gate.receipt_ok(SHA, {}, lambda _: run())

    def test_skip_needs_verified_receipt_and_live_manifest(self):
        calls = []
        def get(path, token):
            calls.append((path, token))
            return {"artifacts": [receipt()]} if "/artifacts?" in path else run()
        public_calls = []
        def public(url):
            public_calls.append(url)
            return {"release": "v1", "build": SHA}
        self.assertTrue(gate.verified_live(SHA, TOKEN, get=get, public=public))
        self.assertEqual(len(public_calls), 1)
        self.assertIn("/release.json?receipt_check=", public_calls[0])
        self.assertTrue(all(token == TOKEN for _, token in calls))

    def test_live_drift_or_outage_triggers_republish(self):
        def get(path, token):
            return {"artifacts": [receipt()]} if "/artifacts?" in path else run()
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get,
                                            public=lambda _: {"build": "b" * 40}))
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=lambda _: {}))
        def offline(_):
            raise TimeoutError("public Pages unavailable")
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=offline))

    def test_live_only_probe_reuses_public_sha_check_without_receipt(self):
        self.assertTrue(gate.live_matches(SHA, public=lambda _: {"build": SHA}))
        self.assertFalse(gate.live_matches(SHA, public=lambda _: {"build": "b" * 40}))
        self.assertFalse(gate.live_matches(SHA, public=lambda _: {"release": "old"}))
        def unreachable(_):
            raise TimeoutError("public HTTPS not responding")
        self.assertFalse(gate.live_matches(SHA, public=unreachable))
        with self.assertRaises(gate.GateError):
            gate.live_matches("not-a-sha", public=lambda _: {"build": SHA})

    def test_public_manifest_must_be_exact_https_200_json_with_no_redirect(self):
        url = gate.ORIGIN + "/release.json?receipt_check=123"
        data = json.dumps({"build": SHA}).encode()
        requests = []

        class Response:
            def __init__(self, body=data, final=url, status=200,
                         mime="application/json; charset=utf-8"):
                self.status = status
                self.headers = {"Content-Type": mime}
                self.final = final
                self.stream = io.BytesIO(body)
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def geturl(self):
                return self.final
            def read(self, n=-1):
                return self.stream.read(n)

        def open_public(req, timeout):
            requests.append((req, timeout))
            return Response()
        self.assertEqual(gate.read_manifest(url, opener=open_public), {"build": SHA})
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][0].full_url, url)
        self.assertEqual(requests[0][1], 15)
        self.assertIsNone(requests[0][0].get_header("Authorization"))
        self.assertEqual(requests[0][0].get_header("Cache-control"), "no-cache")

        for response in (
            Response(final="https://other.example/release.json?receipt_check=123"),
            Response(final=gate.ORIGIN + "/other.json"),
            Response(status=204),
            Response(status=503),
            Response(mime="text/html"),
            Response(mime="application/octet-stream"),
            Response(body=b"<html>SPA fallback</html>"),
            Response(body=b"[]"),
            Response(body=b"null"),
            Response(body=b'{"build":'),
            Response(body=data + b" " * gate.MAX_MANIFEST_BYTES),
        ):
            with self.subTest(response=response.__dict__):
                with self.assertRaises(ValueError):
                    gate.read_manifest(url, opener=lambda req, timeout: response)

        for bad in (
            "http://staging.chronicles.shadowops.dpdns.org/release.json?receipt_check=123",
            "https://evil.example/release.json?receipt_check=123",
            gate.ORIGIN + "/other.json?receipt_check=123",
            gate.ORIGIN + "/release.json",
            gate.ORIGIN + "/release.json?receipt_check=123#fragment",
        ):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "Untrusted"):
                    gate.read_manifest(bad, opener=lambda req, timeout: self.fail("Untrusted request"))

        self.assertEqual(gate.read_manifest(
            url, opener=lambda req, timeout: Response(mime="application/problem+json")),
            {"build": SHA})

    def test_public_manifest_proof_does_not_follow_any_http_redirect(self):
        # Default urllib follows 302; our transport explicitly declines even
        # same-origin redirects, not just redirects to a foreign hostname.
        redirect = gate._NoRedirect()
        req = urllib.request.Request(gate.ORIGIN + "/release.json?receipt_check=123")
        self.assertIsNone(redirect.redirect_request(
            req, None, 302, "Found", {"Location": gate.ORIGIN + "/release.json"},
            gate.ORIGIN + "/release.json"
        ))
        # Full public reader is actually wired to a no-redirect handler.
        class RejectingOpener:
            def open(self, req, timeout):
                self.req = req
                raise ValueError("Redirect blocked")
        fake_transport = RejectingOpener()
        with patch.object(gate.urllib.request, "build_opener", return_value=fake_transport) as builder:
            self.assertFalse(gate.live_matches(SHA))
            builder.assert_called_once()
            self.assertIsInstance(builder.call_args.args[0], gate._NoRedirect)

    def test_live_check_cannot_skip_if_strict_manifest_proof_fails(self):
        url = gate.ORIGIN + "/release.json?receipt_check=123"
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def geturl(self):
                return "https://other.example/release.json"
            def read(self, n=-1):
                return json.dumps({"build": SHA}).encode()
        with patch.object(gate, "read_manifest", side_effect=lambda _:
                          gate.read_manifest(url, opener=lambda req, timeout: Response())):
            self.assertFalse(gate.live_matches(SHA))

    def test_absent_or_untrusted_receipt_never_consults_live_site(self):
        def get(path, token):
            return {"artifacts": []} if "/artifacts?" in path else run()
        def must_not_read(_):
            raise AssertionError("live check requires trusted receipt first")
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=must_not_read))
        with self.assertRaises(gate.GateError):
            gate.verified_live(SHA, "")
        with self.assertRaises(gate.GateError):
            gate.verified_live("bogus", TOKEN)


if __name__ == "__main__":
    unittest.main()
