"""Authenticated GitHub evidence reads must never follow redirects or trust a foreign URL."""
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_api_before_pages as api


class FakeResponse:
    def __init__(self, url, *, body=None, status=200, final=None):
        self.status = status
        self.final = final or url
        self.stream = io.BytesIO(json.dumps({"artifacts": []}).encode() if body is None else body)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit=-1):
        return self.stream.read(limit)

    def geturl(self):
        return self.final


class GithubEvidenceTransportTest(unittest.TestCase):
    def test_authenticated_exact_origin_and_no_redirect_handler(self):
        path = "repos/evilsysadmin/shadowops-infra/actions/artifacts?name=receipt"
        observed = []

        class Opener:
            def open(self, request, timeout):
                observed.append((request, timeout))
                return FakeResponse(request.full_url)

        def create(*handlers):
            self.assertEqual(len(handlers), 1)
            handler = handlers[0]
            self.assertIsInstance(handler, api.RejectGithubRedirects)
            req = urllib.request.Request(
                "https://api.github.com/repos/example/actions/artifacts",
                headers={"Authorization": "Bearer synthetic"})
            for status in (301, 302, 303, 307, 308):
                self.assertIsNone(handler.redirect_request(
                    req, None, status, "redirect",
                    {"Location": "https://attacker.invalid/steal"},
                    "https://attacker.invalid/steal"))
            return Opener()

        with patch.object(api.urllib.request, "build_opener", side_effect=create):
            self.assertEqual(api.fetch(path, "synthetic"), {"artifacts": []})
        request, timeout = observed[0]
        self.assertEqual(timeout, 20)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "https://api.github.com/" + path)
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")

    def test_redirect_status_html_fallback_or_foreign_final_url_fails_closed(self):
        path = "repos/evilsysadmin/shadowops-infra/actions/runs/123"
        endpoint = "https://api.github.com/" + path

        class Transport:
            def __init__(self, response=None, error=None):
                self.response, self.error = response, error
            def open(self, req, timeout):
                if self.error:
                    raise self.error
                return self.response

        cases = (
            Transport(FakeResponse(endpoint, status=302)),
            Transport(FakeResponse(endpoint, final="https://attacker.invalid/steal")),
            Transport(FakeResponse(endpoint, body=b"<html>not json</html>")),
            Transport(FakeResponse(endpoint, body=b"[]")),
            Transport(error=urllib.error.HTTPError(endpoint, 307, "redirect", {}, None)),
        )
        for transport in cases:
            with self.subTest(transport=repr(transport)):
                with patch.object(api.urllib.request, "build_opener", return_value=transport):
                    with self.assertRaises(api.GateError):
                        api.fetch(path, "synthetic")

    def test_missing_token_or_invalid_path_never_attempts_transport(self):
        with patch.object(api.urllib.request, "build_opener") as opener:
            for path, token in (
                ("repos/evilsysadmin/shadowops-infra/actions/runs/1", ""),
                ("https://attacker.invalid/path", "synthetic"),
                ("", "synthetic"),
            ):
                with self.subTest(path=path):
                    with self.assertRaises(api.GateError):
                        api.fetch(path, token)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
