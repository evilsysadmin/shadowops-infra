"""Privacy-safe HTTPS diagnostic for the independent Chronicles Pages hostname."""
import io
import pathlib
import socket
import ssl
import sys
import unittest
import urllib.error
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

    def test_https_errors_are_classified_not_echoed(self):
        cases = [
            (urllib.error.URLError(ssl.SSLCertVerificationError("private cert body")), "tls_error"),
            (urllib.error.URLError(socket.gaierror("private dns details")), "dns_error"),
            (urllib.error.URLError(TimeoutError("private timeout")), "timeout"),
            (urllib.error.URLError(OSError("private host data")), "connection_error"),
            (urllib.error.HTTPError(pages.HOST, 522, "private response", {}, None), "http_error"),
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
