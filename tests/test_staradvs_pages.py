import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "staradvs_pages.py"
spec = importlib.util.spec_from_file_location("staradvs_pages", MODULE)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class FakeCloudflare:
    account = "a" * 32

    def __init__(self, *, foreign=False, project=False, domain=False, duplicates=False):
        self.foreign = foreign
        self.project = project
        self.domain = domain
        self.duplicates = duplicates
        self.dns = False
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path.startswith("/zones?"):
            return 200, [{"name": s.ZONE, "id": "z" * 32}]
        if "/dns_records?" in path:
            if self.foreign:
                result = [{"name": s.HOST, "type": "CNAME", "proxied": True,
                           "content": "foreign.pages.dev"}]
            elif self.dns:
                result = [{"name": s.HOST, "type": "CNAME", "proxied": True,
                           "content": s.TARGET}]
            else:
                result = []
            if self.duplicates:
                result *= 2
            return 200, result
        if path.endswith("/dns_records") and method == "POST":
            assert data["name"] == s.HOST and data["content"] == s.TARGET and data["proxied"] is True
            self.dns = True
            return 200, {"id": "record"}
        if path.endswith("/pages/projects"):
            if method == "POST":
                assert data == {"name": s.PROJECT, "production_branch": "main"}
                self.project = True
                return 201, {"name": s.PROJECT, "production_branch": "main"}
        if path.endswith("/pages/projects/" + s.PROJECT):
            if self.project:
                return 200, {"name": s.PROJECT, "production_branch": "main"}
            return 404, None
        if path.endswith("/domains/" + s.HOST):
            if self.domain:
                return 200, {"name": s.HOST, "status": "active"}
            return 404, None
        if path.endswith("/domains") and method == "POST":
            assert data == {"name": s.HOST}
            self.domain = True
            return 201, {"name": s.HOST, "status": "pending"}
        raise AssertionError("Unknown Cloudflare endpoint " + method + " " + path)


class StagingPagesTests(unittest.TestCase):
    def test_preflight_is_read_only_and_fixed_to_expected_identity(self):
        cf = FakeCloudflare()
        zone, statuses = s.inspect(cf)
        self.assertEqual(zone, "z" * 32)
        self.assertEqual(statuses, {"dns": "absent", "project": "absent", "domain": "absent"})
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))

    def test_foreign_hostname_aborts_before_any_write(self):
        cf = FakeCloudflare(foreign=True)
        with self.assertRaisesRegex(s.AdmissionError, "another target"):
            s.ensure_project(cf)
        with self.assertRaisesRegex(s.AdmissionError, "another target"):
            s.ensure_domain(cf)
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))

    def test_duplicate_or_ambiguous_hostname_aborts(self):
        cf = FakeCloudflare(project=True, domain=True, duplicates=True)
        cf.dns = True
        with self.assertRaisesRegex(s.AdmissionError, "Multiple DNS owners"):
            s.inspect(cf)

    def test_only_dedicated_project_created(self):
        cf = FakeCloudflare()
        s.ensure_project(cf)
        self.assertTrue(cf.project)
        self.assertEqual(len([x for x in cf.calls if x[0] == "POST"]), 1)
        self.assertEqual([p for method, p, _ in cf.calls if method == "POST"],
                         [f"/accounts/{cf.account}/pages/projects"])

    def test_domain_and_dns_created_only_after_owned_project(self):
        cf = FakeCloudflare()
        with self.assertRaisesRegex(s.AdmissionError, "not found"):
            s.ensure_domain(cf)
        self.assertTrue(all(op == "GET" for op, _, _ in cf.calls))
        s.ensure_project(cf)
        s.ensure_domain(cf)
        self.assertTrue(cf.domain and cf.dns)
        self.assertEqual([p for op,p,_ in cf.calls if op == "POST"][-2:],
                         [f"/accounts/{cf.account}/pages/projects/{s.PROJECT}/domains",
                          "/zones/" + "z"*32 + "/dns_records"])
        # Repeated reconciliation never creates a second record.
        before = len([x for x in cf.calls if x[0] == "POST"])
        s.ensure_domain(cf)
        self.assertEqual(len([x for x in cf.calls if x[0] == "POST"]), before)

    def test_existing_owned_resources_are_left_untouched(self):
        cf = FakeCloudflare(project=True, domain=True)
        cf.dns = True
        s.ensure_project(cf)
        s.ensure_domain(cf)
        self.assertTrue(all(op == "GET" for op,_,_ in cf.calls))

    def test_future_or_wrong_sha_rejected_for_live_public_probe(self):
        for sha in ["", "main", "A"*40, "z"*40, "0"*39]:
            with self.assertRaisesRegex(s.AdmissionError, "source SHA"):
                s.public_check(sha)

    def test_live_probe_uses_browser_headers_for_html_js_and_release(self):
        sha = "a" * 40
        calls = []

        class Response:
            status = 200

            def __init__(self, data, mime):
                self.data = data
                self.headers = {"Content-Type": mime}

            def read(self, _limit):
                return self.data

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def urlopen(req, **kwargs):
            calls.append(req)
            self.assertIsNotNone(kwargs.get("context"))  # TLS validation retained
            if req.full_url == s.BASE + "/":
                return Response(b'<title>Star Adventures</title><div id="root"></div><script type="module" src="/assets/index-abcdef.js"></script>', "text/html")
            if req.full_url.endswith("/assets/index-abcdef.js"):
                return Response(b"console.log('staradvs')", "application/javascript")
            if req.full_url == s.BASE + "/release.json":
                return Response(json.dumps({"build": sha, "environment": "staging",
                                            "entry_js": {"path": "/assets/index-abcdef.js",
                                                         "sha256": hashlib.sha256(b"console.log('staradvs')").hexdigest()}}).encode(), "application/json")
            raise AssertionError("Unexpected external URL")

        with patch.object(s.urllib.request, "urlopen", side_effect=urlopen):
            s.public_check(sha)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all("Mozilla/5.0" in req.get_header("User-agent", "") for req in calls))
        self.assertIn("javascript", calls[1].get_header("Accept", ""))
        self.assertEqual(calls[1].full_url, s.BASE + "/assets/index-abcdef.js")

    def test_browser_blocked_asset_is_a_failure_not_an_accepted_game(self):
        sha = "a" * 40
        class Response:
            status = 200
            headers = {"Content-Type": "text/html"}
            def read(self, _):
                return b'<title>Star Adventures</title><div id="root"></div><script src="/assets/index.js"></script>'
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
        def urlopen(req, **_):
            if req.full_url == s.BASE + "/":
                return Response()
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
        with patch.object(s.urllib.request, "urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(s.AdmissionError, "Public JavaScript unavailable \\(HTTP 403\\)"):
                s.public_check(sha)


    def test_build_manifest_contains_real_entrypoint_digest_and_nocache_headers(self):
        sha = "b" * 40
        with tempfile.TemporaryDirectory() as tmp:
            dist = pathlib.Path(tmp)
            (dist / "assets").mkdir()
            js = b"console.log('exact deployed bundle')"
            (dist / "assets/index-genuine.js").write_bytes(js)
            (dist / "index.html").write_bytes(
                b'<div id="root"></div><script type="module" src="/assets/index-genuine.js"></script>'
            )
            s.write_manifest(dist, sha)
            manifest = json.loads((dist / "release.json").read_text())
            self.assertEqual(manifest["build"], sha)
            self.assertEqual(manifest["environment"], "staging")
            self.assertEqual(manifest["entry_js"], {
                "path": "/assets/index-genuine.js",
                "sha256": hashlib.sha256(js).hexdigest(),
            })
            self.assertIn("no-store", (dist / "_headers").read_text())

    def test_manifest_rejects_missing_external_or_ambiguous_js_entries(self):
        sha = "b" * 40
        with tempfile.TemporaryDirectory() as tmp:
            dist = pathlib.Path(tmp)
            (dist / "assets").mkdir()
            index = dist / "index.html"
            for html in (
                b'<script src="https://foreign.test/malicious.js"></script>',
                b'<script src="/assets/../../../secret.js"></script>',
                b'<script src="/assets/a.js"></script><script src="/assets/b.js"></script>',
            ):
                index.write_bytes(html)
                with self.assertRaisesRegex(s.AdmissionError, "exactly one"):
                    s.write_manifest(dist, sha)
            index.write_bytes(b'<script src="/assets/missing.js"></script>')
            with self.assertRaisesRegex(s.AdmissionError, "entrypoint missing"):
                s.write_manifest(dist, sha)

    def test_live_sha_manifest_rejects_mixed_or_stale_javascript_bytes(self):
        sha = "b" * 40
        expected_js = b"build-output-from-sha-b"
        actual_js = b"stale-cdn-entry-from-other-release"
        path = "/assets/index-build.js"

        class Response:
            status = 200
            def __init__(self, data, mime):
                self.data, self.headers = data, {"Content-Type": mime}
            def read(self, _):
                return self.data
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        def urlopen(req, **kwargs):
            self.assertIsNotNone(kwargs.get("context"))
            if req.full_url == s.BASE + "/":
                return Response(
                    b'<title>Star Adventures</title><div id="root"></div><script src="/assets/index-build.js"></script>',
                    "text/html")
            if req.full_url == s.BASE + path:
                return Response(actual_js, "application/javascript")
            if req.full_url == s.BASE + "/release.json":
                return Response(json.dumps({
                    "build": sha, "environment": "staging",
                    "entry_js": {"path": path, "sha256": hashlib.sha256(expected_js).hexdigest()},
                }).encode(), "application/json")
            raise AssertionError("Unexpected request " + req.full_url)

        with patch.object(s.urllib.request, "urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(s.AdmissionError, "differs from built release manifest"):
                s.public_check(sha)

    def test_public_release_without_integrity_contract_is_not_verified(self):
        sha = "b" * 40

        class Response:
            status = 200
            def __init__(self, data, mime):
                self.data, self.headers = data, {"Content-Type": mime}
            def read(self, _):
                return self.data
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        def urlopen(req, **_):
            if req.full_url == s.BASE + "/":
                return Response(
                    b'<title>Star Adventures</title><div id="root"></div><script src="/assets/index.js"></script>',
                    "text/html")
            if req.full_url.endswith("/assets/index.js"):
                return Response(b"console.log(1)", "application/javascript")
            if req.full_url == s.BASE + "/release.json":
                return Response(json.dumps({"build": sha, "environment": "staging"}).encode(), "application/json")
            raise AssertionError("Unexpected request")
        with patch.object(s.urllib.request, "urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(s.AdmissionError, "differs from built release manifest"):
                s.public_check(sha)

    def test_credentials_not_available_without_token(self):
        for env in ({}, {"CLOUDFLARE_API_TOKEN": "foo"}):
            with self.assertRaises(s.AdmissionError):
                s.CloudflareClient(env)



class StarAdventuresWorkflowOwnershipTests(unittest.TestCase):
    def test_pages_contracts_are_owned_by_staging_workflow_only(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        workflow_dir = root / ".github" / "workflows"
        self.assertFalse((workflow_dir / "staradvs-pages-contracts.yml").exists(),
                         "Legacy standalone Pages suite duplicates staging CI")
        workflow = (workflow_dir / "staradvs-pages-staging.yml").read_text(encoding="utf-8")
        for module in ("test_staradvs_pages.py", "test_staradvs_source_admission.py",
                       "test_staradvs_staging_hold.py"):
            self.assertEqual(workflow.count("-p '" + module + "' -v"), 1,
                             "Every shared suite must have exactly one runner")
        self.assertIn("python3 scripts/staradvs_pages.py self-test", workflow)
        self.assertIn("python3 -m py_compile scripts/staradvs_pages.py", workflow)

    def test_shared_pages_changes_trigger_staging_checks(self):
        import re
        root = pathlib.Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/staradvs-pages-staging.yml").read_text(encoding="utf-8")
        path_sections = re.findall(r"(?m)^    paths: \\[(.+)\\]$", workflow)
        self.assertEqual(len(path_sections), 2)
        pr_paths, push_paths = path_sections
        for required in ("tests/test_staradvs_source_admission.py",
                         "tests/test_staradvs_pages.py",
                         "scripts/staradvs_source_admission.py",
                         "scripts/staradvs_pages.py"):
            self.assertIn(required, pr_paths)
            self.assertIn(required, push_paths)
        self.assertIn("docs/staradvs-staging.md", pr_paths)
        self.assertNotIn("docs/staradvs-staging.md", push_paths,
                         "Docs-only main merges should not request a live deployment")

if __name__ == "__main__":
    unittest.main()
