"""Public-hosted React preview admission; all tests offline and no Cloudflare writes."""
import os
import pathlib
import re
import subprocess
import sys
import tempfile
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
    def test_public_game_assets_reject_deceptive_mime_parameters(self):
        # Every response contains plausible content; browser MIME validation,
        # not body length or a substring from a parameter, must reject it.
        html = (
            b'<html><head><title>Chronicles of Matthias</title>'
            b'<script type="module" src="/assets/index-abc.js"></script>'
            b'<link rel="stylesheet" href="/assets/index-def.css">'
            b'<link rel="modulepreload" href="/assets/vendor-xyz.js">'
            b'</head><body><div id="root"></div></body></html>'
        )
        manifest = b'{"orientation":"landscape","display":"standalone","start_url":"./"}'
        responses = {
            "/": (html, "text/html"),
            "/assets/index-abc.js": (JS, "application/javascript"),
            "/assets/index-def.css": (CSS, "text/css"),
            "/assets/vendor-xyz.js": (JS, "text/javascript; charset=utf-8"),
            "/manifest.webmanifest": (manifest, "application/manifest+json"),
        }
        cases = (
            ("/", "application/vnd.text/html+json", "html_missing"),
            ("/assets/index-abc.js", "application/json; note=javascript", "js_mime"),
            ("/assets/index-def.css", "application/vnd.text/css+json", "css_mime"),
            ("/assets/vendor-xyz.js", "application/json; charset=javascript", "preload_mime"),
            ("/manifest.webmanifest", "text/html", "manifest_content"),
        )
        for url_suffix, wrong_mime, expected in cases:
            with self.subTest(asset=url_suffix):
                def serve(req, timeout):
                    self.assertEqual(timeout, 10)
                    self.assertEqual(req.full_url.split(pages.HOST, 1)[0], "https://")
                    self.assertIsNone(req.get_header("Authorization"))
                    content, mime = responses[req.full_url.removeprefix(
                        "https://" + pages.HOST)]
                    if req.full_url.endswith(url_suffix):
                        mime = wrong_mime
                    return FakeResponse(req.full_url, content, mime)
                with patch.object(pages.urllib.request, "urlopen", side_effect=serve):
                    self.assertEqual(pages.probe_react_preview(
                        path="/", assets=b"/assets/",
                        manifest_path="/manifest.webmanifest",
                    ), expected)

        # Explicitly allow standard JS MIME with valid case and charset.
        def valid(req, timeout):
            key = req.full_url.removeprefix("https://" + pages.HOST)
            content, mime = responses[key]
            if key == "/assets/index-abc.js":
                mime = "Text/JavaScript; charset=UTF-8"
            elif key == "/assets/vendor-xyz.js":
                mime = "application/ecmascript; charset=utf-8"
            elif key == "/assets/index-def.css":
                mime = "text/css; charset=UTF-8"
            return FakeResponse(req.full_url, content, mime)
        with patch.object(pages.urllib.request, "urlopen", side_effect=valid):
            self.assertEqual(pages.probe_react_preview(
                path="/", assets=b"/assets/",
                manifest_path="/manifest.webmanifest",
            ), "ok")

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

    def test_full_game_root_allows_cinematic_loader_but_still_requires_real_assets(self):
        # Mirrors frontend/index.html: #root is populated before React hydrates.
        html = HTML.replace(b"/react/assets/", b"/assets/").replace(
            b'<div id="root"></div>',
            b'<div id="root"><main class="chronicles-boot" role="status">'
            b'<img src="/chronicles-loading-crest.svg" alt="">'
            b'<h1>CHRONICLES</h1></main><noscript>JavaScript required</noscript></div>',
        )
        calls = []

        def response(req, timeout):
            calls.append(req.full_url)
            if req.full_url.endswith("/"):
                return FakeResponse(req.full_url, html, "text/html")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            raise AssertionError("Unexpected request " + req.full_url)

        with patch.object(pages.urllib.request, "urlopen", side_effect=response):
            self.assertEqual(
                pages.probe_react_preview(path="/", assets=b"/assets/", manifest_path=None), "ok",
            )
        self.assertEqual(len(calls), 3)
        wrong = html.replace(b'id="root"', b'id="rootish"')
        with patch.object(pages.urllib.request, "urlopen",
                          return_value=FakeResponse("https://" + pages.HOST + "/", wrong, "text/html")):
            self.assertEqual(
                pages.probe_react_preview(path="/", assets=b"/assets/", manifest_path=None),
                "html_missing",
            )

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
            self.assertEqual(timeout, 10)
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Cookie"))
            self.assertIn("Mozilla/5.0", req.get_header("User-agent"))
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
        self.assertIn("https://" + pages.HOST + "/assets/vendor-CoSDG3-6.js", requested)
        self.assertIn("https://" + pages.HOST + "/assets/vendor-react-BRcWHSNz.js", requested)
        self.assertEqual(len(requested), 5)

    def test_modulepreload_absence_html_fallback_redirect_and_mime_are_rejected(self):
        html = (b'<!doctype html><html><head><title>Chronicles of Matthias</title>'
                b'<script type="module" src="/assets/index-abc.js"></script>'
                b'<link rel="stylesheet" href="/assets/index-def.css">'
                b'<link rel="modulepreload" href="/assets/vendor-xyz.js">'
                b'</head><body><div id="root"></div></body></html>')
        urls = []

        def serve(req, timeout):
            urls.append(req.full_url)
            if req.full_url.endswith("/"):
                return FakeResponse(req.full_url, html, "text/html")
            if req.full_url.endswith("/assets/index-abc.js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith("/assets/index-def.css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            if req.full_url.endswith("/assets/vendor-xyz.js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            raise AssertionError("Unexpected URL")

        with patch.object(pages.urllib.request, "urlopen", side_effect=serve):
            self.assertEqual(pages.probe_react_preview(path="/", assets=b"/assets/",
                             manifest_path=None), "ok")
        self.assertIn("https://" + pages.HOST + "/assets/vendor-xyz.js", urls)

        def broken(req, timeout):
            response = serve(req, timeout)
            if req.full_url.endswith("/assets/vendor-xyz.js"):
                return FakeResponse(req.full_url, b"<html>SPA fallback</html>", "text/html")
            return response
        with patch.object(pages.urllib.request, "urlopen", side_effect=broken):
            self.assertEqual(pages.probe_react_preview(path="/", assets=b"/assets/",
                             manifest_path=None), "preload_mime")

        def redirect(req, timeout):
            response = serve(req, timeout)
            if req.full_url.endswith("/assets/vendor-xyz.js"):
                return FakeResponse(req.full_url, JS, "application/javascript",
                                    redirect="https://foreign.invalid/vendor.js")
            return response
        with patch.object(pages.urllib.request, "urlopen", side_effect=redirect):
            self.assertEqual(pages.probe_react_preview(path="/", assets=b"/assets/",
                             manifest_path=None), "preload_mime")

        def missing(req, timeout):
            if req.full_url.endswith("/assets/vendor-xyz.js"):
                raise urllib.error.HTTPError(req.full_url, 404, "private", {}, None)
            return serve(req, timeout)
        with patch.object(pages.urllib.request, "urlopen", side_effect=missing):
            self.assertEqual(pages.probe_react_preview(path="/", assets=b"/assets/",
                             manifest_path=None), "http_404")

        def truncated(req, timeout):
            if req.full_url.endswith("/assets/vendor-xyz.js"):
                return FakeResponse(req.full_url, b"// tiny", "application/javascript")
            return serve(req, timeout)
        with patch.object(pages.urllib.request, "urlopen", side_effect=truncated):
            self.assertEqual(pages.probe_react_preview(path="/", assets=b"/assets/",
                             manifest_path=None), "preload_content")

    def test_modulepreload_references_are_bounded_and_same_origin(self):
        head = (b'<!doctype html><html><head><title>Chronicles of Matthias</title>'
                b'<script type="module" src="/assets/index-abc.js"></script>'
                b'<link rel="stylesheet" href="/assets/index-def.css">')
        tail = b'</head><body><div id="root"></div></body></html>'

        for href in (b'https://foreign.invalid/x.js', b'//foreign.invalid/x.js',
                     b'/other/vendor.js', b'/assets/vendor.js?mutable=1',
                     b'/assets/../vendor.js', b'/assets/vendor.css', b''):
            with self.subTest(href=href):
                html = (head + b'<link rel="modulepreload" href="' + href + b'">' + tail)
                requests = []
                def serve(req, timeout):
                    requests.append(req.full_url)
                    if req.full_url.endswith("/"):
                        return FakeResponse(req.full_url, html, "text/html")
                    if req.full_url.endswith(".js"):
                        return FakeResponse(req.full_url, JS, "application/javascript")
                    return FakeResponse(req.full_url, CSS, "text/css")
                with patch.object(pages.urllib.request, "urlopen", side_effect=serve):
                    self.assertEqual(pages.probe_react_preview(
                        path="/", assets=b"/assets/", manifest_path=None),
                        "preload_reference")
                self.assertTrue(all("foreign.invalid" not in url for url in requests))

        many = b"".join(
            b'<link rel="modulepreload" href="/assets/vendor-' +
            str(n).encode("ascii") + b'.js">' for n in range(17)
        )
        def serve_too_many(req, timeout):
            if req.full_url.endswith("/"):
                return FakeResponse(req.full_url, head + many + tail, "text/html")
            if req.full_url.endswith(".js"):
                return FakeResponse(req.full_url, JS, "application/javascript")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            raise AssertionError("Unexpected preload request")
        with patch.object(pages.urllib.request, "urlopen",
                          side_effect=serve_too_many) as opened:
            self.assertEqual(pages.probe_react_preview(
                path="/", assets=b"/assets/", manifest_path=None),
                "preload_reference")
        self.assertEqual(opened.call_count, 3)

    def test_modulepreload_duplicates_and_attribute_order_are_supported(self):
        html = (b'<!doctype html><html><head><title>Chronicles of Matthias</title>'
                b'<script type="module" src="/assets/index-abc.js"></script>'
                b'<link rel="stylesheet" href="/assets/index-def.css">'
                b'<link href="/assets/vendor-xyz.js" crossorigin rel="modulepreload">'
                b'<link rel="modulepreload" href="/assets/vendor-xyz.js">'
                b'</head><body><div id="root"></div></body></html>')
        requests = []
        def serve(req, timeout):
            requests.append(req.full_url)
            if req.full_url.endswith("/"):
                return FakeResponse(req.full_url, html, "text/html")
            if req.full_url.endswith(".css"):
                return FakeResponse(req.full_url, CSS, "text/css")
            return FakeResponse(req.full_url, JS, "application/javascript")
        with patch.object(pages.urllib.request, "urlopen", side_effect=serve):
            self.assertEqual(pages.probe_react_preview(
                path="/", assets=b"/assets/", manifest_path=None), "ok")
        self.assertEqual(requests.count("https://" + pages.HOST +
                                        "/assets/vendor-xyz.js"), 1)

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
            "test -s dist/release.json", "m.build!==process.env.VITE_BUILD_SHA",
            "ChroniclesOfMatthias-*.js", "ChroniclesOfMatthiasTactics-*.js",
            "chroniclesOfMatthiasThree-*.js", "/chronicles/runs",
            "VITE_API_URL: https://chronicles-api-staging.shadowops.dpdns.org/api",
            'cp -a chronicles-source/frontend/dist/. "$root/"',
            'wrangler@4.127.1 pages deploy "$RUNNER_TEMP/chronicles-pages"',
        ]:
            self.assertIn(required, workflow)
        self.assertIn("EXPECTED_SHA: ${{ steps.source.outputs.sha }}", workflow)
        self.assertIn("python3 scripts/chronicles_pages_manifest_wait.py", workflow)
        helper = (pathlib.Path(__file__).resolve().parents[1]
                  / "scripts/chronicles_pages_manifest_wait.py").read_text()
        for guard in ("CHRONICLES_PUBLIC_RELEASE_MANIFEST_OK",
                      'manifest.get("build") == sha',
                      "from chronicles_pages_verified_receipt import ORIGIN, read_manifest"):
            self.assertIn(guard, helper)
        self.assertIn('chronicles_api_before_pages.py "$ADMITTED_SHA"', workflow)
        self.assertIn("needs: [contracts, staging-candidate, api-ready]", workflow)
        self.assertIn("if: needs.api-ready.outputs.publish == 'true'", workflow)
        self.assertIn("CHRONICLES_PAGES_SUPERSEDED_BEFORE_RELEASE", workflow)
        self.assertIn("echo 'publish=false' >> \"$GITHUB_OUTPUT\"", workflow)
        self.assertLess(workflow.index('chronicles_api_before_pages.py "$ADMITTED_SHA"'),
                        workflow.index("scripts/chronicles_pages.py preflight"))
        self.assertNotIn("wrangler pages deploy chronicles-source/frontend", workflow)
        self.assertIn("python3 scripts/chronicles_source_ci.py \"$sha\"", workflow)
        self.assertIn("source_sha: ${{ steps.check.outputs.source_sha }}", workflow)
        self.assertLess(workflow.index("scripts/pages_owner_admission.py"),
                        workflow.index("npm run build"))
        # Chronicles owns its source: no dependency on a Chess Studio checkout.
        self.assertNotIn("evilsysadmin/chess-studio", workflow)


class PagesSupersededReleaseTests(unittest.TestCase):
    """Run the actual staging freshness shell snippets with an offline fake gh."""

    @staticmethod
    def staging_workflow():
        return (pathlib.Path(__file__).resolve().parents[1] /
                ".github/workflows/chronicles-pages-release.yml").read_text().split(
                    "\n  production:\n", 1)[0]

    def run_step(self, name, current):
        workflow = self.staging_workflow()
        block = workflow.split("      - name: " + name + "\n", 1)[1].split(
            "\n      - name:", 1)[0]
        source = block.split("\n        run: |\n", 1)[1]
        lines = source.splitlines()
        script = "\n".join(line[10:] for line in lines if line.startswith("          "))
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_gh = root / "gh"
            fake_gh.write_text('#!/bin/sh\n'
                               'test "$1" = api || exit 3\n'
                               'echo "$MOCK_MAIN_SHA"\n')
            fake_gh.chmod(0o755)
            fake_npx = root / "npx"
            fake_npx.write_text('#!/bin/sh\necho ran > "$RUNNER_TEMP/npx-ran"\n')
            fake_npx.chmod(0o755)
            output, summary = root / "output", root / "summary"
            env = {**os.environ,
                   "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "MOCK_MAIN_SHA": current,
                   "ADMITTED_SHA": "a" * 40,
                   "CHRONICLES_SOURCE_SHA": "a" * 40,
                   "GITHUB_OUTPUT": str(output),
                   "GITHUB_STEP_SUMMARY": str(summary),
                   "RUNNER_TEMP": directory}
            process = subprocess.run(["bash", "-c", script], env=env,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            return (process.returncode, process.stdout,
                    output.read_text() if output.exists() else "",
                    summary.read_text() if summary.exists() else "",
                    (root / "npx-ran").exists())

    def test_stale_build_skips_without_wrangler_or_deployment_receipt(self):
        for name, result in (
            ("Skip superseded source before Pages mutations", "fresh=false"),
            ("Publish exact source SHA to the isolated Pages project",
             "published=false"),
        ):
            with self.subTest(step=name):
                code, stdout, output, summary, npx = self.run_step(name, "b" * 40)
                self.assertEqual(code, 0)
                self.assertIn(result, output)
                self.assertIn("superseded", summary.lower())
                self.assertIn("SUPERSEDED_", stdout)
                self.assertFalse(npx)

    def test_current_build_preserves_actual_publish_and_fail_closed_errors(self):
        before = self.run_step("Skip superseded source before Pages mutations", "a" * 40)
        self.assertEqual(before[0], 0)
        self.assertIn("fresh=true", before[2])
        matching = self.run_step("Publish exact source SHA to the isolated Pages project",
                                 "a" * 40)
        self.assertEqual(matching[0], 0)
        self.assertIn("published=true", matching[2])
        self.assertTrue(matching[4])
        for step in ("Skip superseded source before Pages mutations",
                     "Publish exact source SHA to the isolated Pages project"):
            with self.subTest(step=step):
                code, stdout, output, summary, npx = self.run_step(step, "invalid-sha")
                self.assertNotEqual(code, 0)
                self.assertNotIn("fresh=false", output)
                self.assertNotIn("published=false", output)
                self.assertFalse(npx)

    def test_skip_never_runs_public_smoke_or_emits_verified_receipt(self):
        workflow = self.staging_workflow()
        self.assertIn("id: source_pre_publish", workflow)
        self.assertIn("id: deploy", workflow)
        for name in (
            "Reconcile independent Chronicles Pages project",
            "Publish exact source SHA to the isolated Pages project",
        ):
            block = workflow.split("      - name: " + name + "\n", 1)[1].split(
                "\n      - name:", 1)[0]
            self.assertIn("steps.source_pre_publish.outputs.fresh == 'true'", block)
        for name in (
            "Prove the public game build at root",
            "Prove the public update manifest serves the exact SHA",
            "Verify lockfile-pinned Playwright browser harness",
            "Cache exact Chromium browser binaries",
            "Real public browser smoke (desktop, mobile, login, update deferral)",
            "Reject superseded source before writing verified receipt",
        ):
            block = workflow.split("      - name: " + name + "\n", 1)[1].split(
                "\n      - name:", 1)[0]
            self.assertIn(
                "steps.live.outputs.already_published == 'true' || "
                "steps.deploy.outputs.published == 'true'", block)
        # Stale generations are now also filtered before both checkouts.
        # Keep the original receipt/deploy predicates AND the entry gate.
        self.assertIn(
            "if: steps.entry_freshness.outputs.fresh == 'true' && "
            "(steps.source_freshness.outputs.fresh == 'true')\n"
            "        uses: actions/upload-artifact@v4", workflow)
        self.assertIn(
            "if: steps.entry_freshness.outputs.fresh == 'true' && "
            "(steps.deploy.outputs.published == 'true')", workflow)


if __name__ == "__main__":
    unittest.main()
