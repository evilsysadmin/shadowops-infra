"""Public-hosted React preview admission; all tests offline and no Cloudflare writes."""
import pathlib
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages as pages

HTML = (b'<!doctype html><html><head><title>Chronicles of Matthias</title>'
        b'<script type="module" crossorigin src="/react/assets/index-abc_123.js"></script>'
        b'<link rel="stylesheet" crossorigin href="/react/assets/index-def_456.css">'
        b'</head><body><div id="root"></div></body></html>')
JS = b'/* standalone React bundle */' + b'x' * 400
CSS = b'/* character creator and original Chronicle styles */' + b'y' * 400


class FakeResponse:
    status = 200

    def __init__(self, url, content, mime, redirect=None):
        self.url = redirect or url
        self.content = content
        self.headers = {"Content-Type": mime}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, size):
        return self.content[:size]


class ParallelReactPagesTest(unittest.TestCase):
    def test_verified_html_and_both_bundles_are_public_same_origin(self):
        requested = []
        def request(req, timeout):
            requested.append(req)
            self.assertEqual(timeout, 10)
            self.assertTrue(req.full_url.startswith("https://" + pages.HOST + "/react/"))
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Cookie"))
            self.assertIn("Mozilla/5.0", req.get_header("User-agent"))
            if req.full_url.endswith("/react/"):
                return FakeResponse(req.full_url, HTML, "text/html; charset=utf-8")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            raise AssertionError("Unexpected asset path " + req.full_url)
        with patch.object(pages.urllib.request, "urlopen", side_effect=request):
            self.assertEqual(pages.probe_react_preview(), "ok")
        self.assertEqual(len(requested), 3)

    def test_rejects_html_fallback_mismatched_root_or_missing_asset(self):
        def html_only(req, timeout):
            return FakeResponse(req.full_url, b'<html>not React</html>', "text/html")
        with patch.object(pages.urllib.request, "urlopen", side_effect=html_only):
            self.assertEqual(pages.probe_react_preview(), "html_missing")

        def wrong_js(req, timeout):
            if req.full_url.endswith("/react/"):
                return FakeResponse(req.full_url, HTML, "text/html")
            return FakeResponse(req.full_url, b'<!doctype html>' + b'x'*400, "text/html")
        with patch.object(pages.urllib.request, "urlopen", side_effect=wrong_js):
            self.assertEqual(pages.probe_react_preview(), "js_mime")

        def redirects(req, timeout):
            return FakeResponse(req.full_url, HTML, "text/html", "https://other.example.com/React")
        with patch.object(pages.urllib.request, "urlopen", side_effect=redirects):
            self.assertEqual(pages.probe_react_preview(), "html_missing")

    def test_http_status_never_exposes_sensitive_payloads(self):
        private = urllib.error.HTTPError(pages.HOST, 403, "SECRET RESPONSE", {}, None)
        with patch.object(pages.urllib.request, "urlopen", side_effect=private):
            self.assertEqual(pages.probe_react_preview(), "http_403")

    def test_source_sha_and_fallback_are_preserved_in_deploy(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1]
                    / ".github/workflows/chronicles-pages-release.yml").read_text()
        for required in [
            "ref: main", "CHRONICLES_SOURCE_SHA:", "CHRONICLES_DEPLOY_BASE: /react/",
            "node --test test/*.test.mjs", "npm run build",
            'cp -a chronicles-source/web/. "$root/"',
            'cp -a chronicles-source/frontend/dist/. "$root/react/"',
            'wrangler@4.127.1 pages deploy "$RUNNER_TEMP/chronicles-pages"',
        ]:
            self.assertIn(required, workflow)
        self.assertNotIn("wrangler pages deploy chronicles-source/frontend", workflow)
        self.assertLess(workflow.index("scripts/pages_owner_admission.py"),
                        workflow.index("npm run build"))


if __name__ == "__main__":
    unittest.main()
