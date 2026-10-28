"""Cloudflare Worker first-install guard: mock responses only, no network."""
from pathlib import Path
import io
import os
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_scheduler_occupancy as guard

ACCOUNT = "a" * 32
TOKEN = "sensitive-token"


class Response:
    def __init__(self, url):
        self.url = url

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class WorkerOccupancyTests(unittest.TestCase):
    def url(self):
        return f"{guard.API_ROOT}/{ACCOUNT}/workers/scripts/{guard.SCRIPT_NAME}"

    def test_exact_authenticated_404_allows_first_install(self):
        calls = []
        def opener(req, timeout):
            calls.append((req, timeout))
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        guard.assert_worker_absent(ACCOUNT, TOKEN, opener=opener)
        request, timeout = calls[0]
        self.assertEqual(timeout, 15)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, self.url())
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")
        self.assertNotIn("Cookie", request.headers)

    def test_existing_worker_is_never_overwritten(self):
        with self.assertRaisesRegex(guard.OccupancyError, "already exists"):
            guard.assert_worker_absent(
                ACCOUNT, TOKEN, opener=lambda req, timeout: Response(req.full_url))

    def test_non404_or_redirected_404_fails_closed(self):
        for status in (400, 401, 403, 408, 409, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(guard.OccupancyError):
                guard.assert_worker_absent(
                    ACCOUNT, TOKEN,
                    opener=lambda req, timeout: (_ for _ in ()).throw(
                        urllib.error.HTTPError(req.full_url, status, "provider", {}, None)))
        with self.assertRaisesRegex(guard.OccupancyError, "cannot be verified"):
            guard.assert_worker_absent(
                ACCOUNT, TOKEN,
                opener=lambda req, timeout: (_ for _ in ()).throw(
                    urllib.error.HTTPError(
                        "https://untrusted.example/worker", 404, "Not Found", {}, None)))
        with self.assertRaisesRegex(guard.OccupancyError, "response origin"):
            guard.assert_worker_absent(
                ACCOUNT, TOKEN,
                opener=lambda req, timeout: Response("https://untrusted.example/worker"))

    def test_bad_id_or_absent_token_never_calls_provider(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("should not call API")
        for value in ("", "not-an-id", "A" * 32, ACCOUNT + "/other", ACCOUNT + "\\n"):
            with self.subTest(value=value), self.assertRaises(guard.OccupancyError):
                guard.assert_worker_absent(value, TOKEN, opener=forbidden)
        for token in ("", " ", None):
            with self.subTest(token=token), self.assertRaises(guard.OccupancyError):
                guard.assert_worker_absent(ACCOUNT, token, opener=forbidden)

    def test_main_only_logs_safe_error_without_provider_body_or_token(self):
        env = {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT, "CLOUDFLARE_API_TOKEN": TOKEN}
        with patch.dict(os.environ, env), patch.object(
            guard, "assert_worker_absent",
            side_effect=urllib.error.URLError("secret response: " + TOKEN),
        ):
            with patch("sys.stderr", new_callable=io.StringIO) as output:
                self.assertEqual(guard.main(), 1)
            self.assertIn("CHRONICLES_SCHEDULER_OCCUPANCY_BLOCKED", output.getvalue())
            self.assertNotIn(TOKEN, output.getvalue())


if __name__ == "__main__":
    unittest.main()
