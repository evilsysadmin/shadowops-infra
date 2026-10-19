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
            if req.full_url.endswith("/manifest.webmanifest"):
                return FakeResponse(req.full_url, b'{"orientation":"landscape","display":"standalone","start_url":"./"}', "application/manifest+json")
            raise AssertionError("Unexpected asset path " + req.full_url)
        with patch.object(pages.urllib.request, "urlopen", side_effect=request):
            self.assertEqual(pages.probe_react_preview(), "ok")
        self.assertEqual(len(requested), 4)

    def test_root_html_scripts_css_and_manifest_are_real_react_assets(self):
        root_html = HTML.replace(b"/react/assets/", b"/assets/")
        requested = []

        def request(req, timeout):
            requested.append(req.full_url)
            self.assertTrue(req.full_url.startswith("https://" + pages.HOST + "/"))
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Cookie"))
            if req.full_url == "https://" + pages.HOST + "/":
                return FakeResponse(req.full_url, root_html, "text/html")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            if req.full_url.endswith("/manifest.webmanifest"):
                return FakeResponse(req.full_url,
                    b'{"orientation":"landscape","display":"standalone","start_url":"./"}',
                    "application/manifest+json")
            raise AssertionError("Bad root asset path")

        with patch.object(pages.urllib.request, "urlopen", side_effect=request):
            self.assertEqual(pages.probe_react_preview(
                path="/", assets=b"/assets/", manifest_path="/manifest.webmanifest",
            ), "ok")
        self.assertEqual(len(requested), 4)
        self.assertEqual(requested[0], "https://" + pages.HOST + "/")
        self.assertTrue(any("/assets/" in value for value in requested))

    def test_vite_modulepreload_links_do_not_hide_the_entry_script(self):
        # Real root HTML of the verbatim game build: one entry module, one
        # stylesheet and several vendor modulepreload links.
        html = (b'<!doctype html><html><head><title>Chronicles of Matthias</title>'
                b'<script type="module" crossorigin src="/assets/index-O94sP1mA.js"></script>'
                b'<link rel="modulepreload" crossorigin href="/assets/vendor-CoSDG3-6.js">'
                b'<link rel="modulepreload" crossorigin href="/assets/vendor-react-BRcWHSNz.js">'
                b'<link rel="stylesheet" crossorigin href="/assets/index-BDG1Thnq.css">'
                b'</head><body><div id="root"></div></body></html>')
        requested = []

        def request(req, timeout):
            requested.append(req.full_url)
            if req.full_url == "https://" + pages.HOST + "/":
                return FakeResponse(req.full_url, html, "text/html")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            raise AssertionError("Unexpected asset path " + req.full_url)

        with patch.object(pages.urllib.request, "urlopen", side_effect=request):
            self.assertEqual(pages.probe_react_preview(
                path="/", assets=b"/assets/", manifest_path=None), "ok")
        self.assertIn("https://" + pages.HOST + "/assets/index-O94sP1mA.js", requested)
        self.assertNotIn("https://" + pages.HOST + "/assets/vendor-CoSDG3-6.js", requested)

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

    def test_missing_or_stale_landscape_manifest_fails_closed(self):
        def request(req, timeout):
            if req.full_url.endswith("/react/"):
                return FakeResponse(req.full_url, HTML, "text/html")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            if req.full_url.endswith("/manifest.webmanifest"):
                return FakeResponse(req.full_url, b'{"orientation":"portrait"}', "application/json")
            raise AssertionError("Unexpected path")
        with patch.object(pages.urllib.request, "urlopen", side_effect=request):
            self.assertEqual(pages.probe_react_preview(), "manifest_content")

    def test_http_status_never_exposes_sensitive_payloads(self):
        private = urllib.error.HTTPError(pages.HOST, 403, "SECRET RESPONSE", {}, None)
        with patch.object(pages.urllib.request, "urlopen", side_effect=private):
            self.assertEqual(pages.probe_react_preview(), "http_403")

    def test_deploy_publishes_the_chronicles_game(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1]
                    / ".github/workflows/chronicles-pages-release.yml").read_text()
        for required in [
            "ref: ${{ needs.staging-candidate.outputs.source_sha }}",
            "CHRONICLES_SOURCE_SHA:", "CHRONICLES_DEPLOY_BASE: /",
            "dist/audio/orchestra/violin-fs3.mp3", "dist/models/matthias-home-canonical.glb",
            "npm ci", "npm run build",
            "ChroniclesOfMatthias-*.js", "ChroniclesOfMatthiasTactics-*.js",
            "chroniclesOfMatthiasThree-*.js", "/chronicles/runs",
            "VITE_API_URL: https://chronicles-api-staging.shadowops.dpdns.org/api",
            'cp -a chronicles-source/frontend/dist/. "$root/"',
            'wrangler@4.127.1 pages deploy "$RUNNER_TEMP/chronicles-pages"',
        ]:
            self.assertIn(required, workflow)
        self.assertNotIn("wrangler pages deploy chronicles-source/frontend", workflow)
        self.assertIn("python3 scripts/chronicles_source_ci.py \"$sha\"", workflow)
        self.assertIn("source_sha: ${{ steps.check.outputs.source_sha }}", workflow)
        self.assertLess(workflow.index("scripts/pages_owner_admission.py"),
                        workflow.index("npm run build"))
        # Chronicles owns its source: no dependency on a Chess Studio checkout.
        self.assertNotIn("evilsysadmin/chess-studio", workflow)

if __name__ == "__main__":
    unittest.main()
