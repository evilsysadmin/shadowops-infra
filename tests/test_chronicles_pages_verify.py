"""Privacy-safe HTTPS diagnostic for the independent Chronicles Pages hostname."""
import io
import pathlib
import socket
import ssl
import sys
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages as pages


class HTTPSVerification(unittest.TestCase):
    def setUp(self):
        self.account = patch.dict(pages.os.environ, {"CLOUDFLARE_ACCOUNT_ID": "test-account"})
        self.account.start()
        self.addCleanup(self.account.stop)

    def test_exact_independent_html_is_required(self):
        class Response:
            status = 200
            def __init__(self, html):
                self.html = html
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return self.html.encode("utf-8")
        good = "CHRONICLES OF MATTHIAS — todavía no es el juego"
        with patch.object(pages.urllib.request, "urlopen", return_value=Response(good)):
            self.assertEqual(pages.probe_https(), "ok")
        with patch.object(pages.urllib.request, "urlopen", return_value=Response("wrong project")):
            self.assertEqual(pages.probe_https(), "unexpected_content")

    def test_https_probe_is_a_public_browser_request_without_auth(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return "CHRONICLES OF MATTHIAS — todavía no es el juego".encode("utf-8")
        with patch.object(pages.urllib.request, "urlopen", return_value=Response()) as open_page:
            self.assertEqual(pages.probe_https(), "ok")
        request = open_page.call_args.args[0]
        self.assertIsInstance(request, urllib.request.Request)
        self.assertEqual(request.full_url, "https://" + pages.HOST + "/")
        self.assertIn("Mozilla/5.0", request.get_header("User-agent"))
        self.assertIn("text/html", request.get_header("Accept"))
        self.assertIsNone(request.get_header("Authorization"))
        self.assertIsNone(request.get_header("Cookie"))

    def test_exploration_modules_require_real_js_and_public_browser_headers(self):
        class Response:
            status = 200
            headers = {"Content-Type": "application/javascript; charset=utf-8"}
            def __init__(self, data):
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return self.data

        requested = []
        def open_asset(req, timeout):
            requested.append(req)
            asset = next(item for item in pages.EXPLORATION_ASSETS
                         if req.full_url.endswith(item[1]))
            return Response(b"// authentic source\n" + asset[2] + b"()")
        with patch.object(pages.urllib.request, "urlopen", side_effect=open_asset):
            self.assertEqual(pages.probe_exploration_assets(), "ok")
        self.assertEqual(len(requested), len(pages.EXPLORATION_ASSETS))
        for req in requested:
            self.assertEqual(req.full_url.split("/game/")[0], "https://" + pages.HOST)
            self.assertIn("Mozilla/5.0", req.get_header("User-agent"))
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Cookie"))

    def test_exploration_missing_asset_and_html_fallback_fail_closed(self):
        class Response:
            status = 200
            def __init__(self, mime, data):
                self.headers = {"Content-Type": mime}
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return self.data
        with patch.object(pages.urllib.request, "urlopen",
                          return_value=Response("text/html", b"<html>404</html>")):
            self.assertEqual(pages.probe_exploration_assets(), "map_response")
        with patch.object(pages.urllib.request, "urlopen",
                          return_value=Response("text/javascript", b"wrong version")):
            self.assertEqual(pages.probe_exploration_assets(), "map_content")
        with patch.object(pages.urllib.request, "urlopen",
                          side_effect=urllib.error.HTTPError(pages.HOST, 404, "private", {}, None)):
            self.assertEqual(pages.probe_exploration_assets(), "map_http_404")

    def test_https_errors_are_classified_not_echoed(self):
        cases = [
            (urllib.error.URLError(ssl.SSLCertVerificationError("private cert body")), "tls_error"),
            (urllib.error.URLError(socket.gaierror("private dns details")), "dns_error"),
            (urllib.error.URLError(TimeoutError("private timeout")), "timeout"),
            (urllib.error.URLError(OSError("private host data")), "connection_error"),
            (urllib.error.HTTPError(pages.HOST, 403, "private policy", {}, None), "http_403"),
            (urllib.error.HTTPError(pages.HOST, 403, "private challenge", {"cf-mitigated": "challenge"}, None), "http_403_challenge"),
            (urllib.error.HTTPError(pages.HOST, 522, "private origin", {}, None), "http_522"),
        ]
        for exception, expected in cases:
            with self.subTest(expected=expected), patch.object(
                pages.urllib.request, "urlopen", side_effect=exception
            ):
                self.assertEqual(pages.probe_https(), expected)

    def verify_once(self, state, probe):
        calls = []
        def cloudflare(method, path):
            calls.append((method, path))
            return 200, {"status": state}
        with patch.object(pages, "request", side_effect=cloudflare), \
             patch.object(pages, "probe_https", return_value=probe), \
             patch.object(pages, "probe_exploration_assets", return_value="ok"), \
             patch.object(pages, "probe_react_preview", return_value="ok"), \
             patch.object(pages.time, "monotonic", side_effect=[0, 0, 2]), \
             patch.object(pages.time, "sleep") as sleeper:
            with redirect_stdout(io.StringIO()):
                try:
                    pages.verify(timeout_seconds=1)
                finally:
                    self.assertTrue(calls)
                    self.assertTrue(all(method == "GET" and path == pages.domain_path()
                                        for method, path in calls))
                    if state != "active" or probe != "ok":
                        sleeper.assert_called_once_with(5)

    def test_pending_tls_failure_is_specific_and_redacted(self):
        with self.assertRaisesRegex(RuntimeError, "domain_status=pending, https_probe=tls_error"):
            self.verify_once("pending", "tls_error")

    def test_pending_html_does_not_pass_release_gate(self):
        with self.assertRaisesRegex(RuntimeError, "domain_status=pending, https_probe=ok"):
            self.verify_once("pending", "ok")

    def test_active_matching_html_passes(self):
        self.verify_once("active", "ok")

    def test_unknown_domain_status_is_not_echoed(self):
        with self.assertRaisesRegex(RuntimeError, "domain_status=unknown, https_probe=connection_error") as caught:
            self.verify_once("sensitive-data-from-provider", "connection_error")
        self.assertNotIn("sensitive-data-from-provider", str(caught.exception))

    def test_blocked_domain_aborts_without_https_probe_or_mutation(self):
        with patch.object(pages, "request", return_value=(200, {"status": "blocked"})) as req, \
             patch.object(pages, "probe_https") as probe, \
             patch.object(pages.time, "monotonic", side_effect=[0, 0]):
            with self.assertRaisesRegex(RuntimeError, "activation failed"):
                pages.verify(timeout_seconds=1)
        req.assert_called_once_with("GET", pages.domain_path())
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
