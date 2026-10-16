"""Read-only early custom hostname admission before first Pages release."""
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages as pages


class TargetPreflight(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.env = patch.dict(pages.os.environ, {"CLOUDFLARE_ACCOUNT_ID": "test-account"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def check(self, *, dns=None, project=None, domain=None):
        def read(method, path, payload=None):
            self.calls.append((method, path))
            if method != "GET" or payload is not None:
                raise AssertionError("Preflight cannot write to Cloudflare")
            if path.startswith("/zones?"):
                return 200, [{"name": pages.ZONE, "id": "test-zone"}]
            if path.startswith("/zones/test-zone/dns_records?"):
                return 200, [] if dns is None else dns
            if path == pages.project_path():
                return (404, None) if project is None else (200, project)
            if path == pages.domain_path():
                return (404, None) if domain is None else (200, domain)
            raise AssertionError("Unexpected Cloudflare path " + path)
        with patch.object(pages, "request", side_effect=read):
            pages.preflight()
        self.assertTrue(self.calls)
        self.assertTrue(all(method == "GET" for method, _ in self.calls))

    def test_accepts_absent_dns_and_pages(self):
        self.check()

    def test_accepts_exact_pages_project_and_proxied_cname(self):
        self.check(dns=[{"name": pages.HOST, "type": "CNAME",
                         "proxied": True, "content": pages.TARGET + "."}],
                   project={"name": pages.PROJECT, "production_branch": "main"},
                   domain={"name": pages.HOST, "status": "active"})

    def test_refuses_competing_origin(self):
        for origin, proxied in (("some-tunnel.cfargotunnel.com", True),
                                ("unrelated.pages.dev", True), (pages.TARGET, False)):
            with self.subTest(origin=origin), self.assertRaisesRegex(RuntimeError, "different origin"):
                self.check(dns=[{"name": pages.HOST, "type": "CNAME",
                                 "content": origin, "proxied": proxied}])

    def test_refuses_ambiguous_dns_and_foreign_pages(self):
        row = {"name": pages.HOST, "type": "CNAME",
               "content": pages.TARGET, "proxied": True}
        with self.assertRaisesRegex(RuntimeError, "Ambiguous"):
            self.check(dns=[row, row])
        with self.assertRaisesRegex(RuntimeError, "not Chronicles"):
            self.check(project={"name": "foreign-pages", "production_branch": "main"})
        with self.assertRaisesRegex(RuntimeError, "does not belong"):
            self.check(project={"name": pages.PROJECT, "production_branch": "main"},
                       domain={"name": "wrong.example", "status": "active"})

    def test_workflow_only_writes_after_preflight_from_protected_main(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-pages-release.yml").read_text()
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        a = workflow.index("scripts/chronicles_pages.py preflight")
        b = workflow.index("scripts/chronicles_pages.py project")
        c = workflow.index("wrangler@")
        d = workflow.index("scripts/chronicles_pages.py domain")
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertLess(c, d)
        self.assertNotIn("pull_request_target", workflow)


if __name__ == "__main__":
    unittest.main()
