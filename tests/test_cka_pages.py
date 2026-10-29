import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cka_pages", ROOT / "scripts" / "cka_pages.py")
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)


class CkaPagesContracts(unittest.TestCase):
    def test_fixed_identity(self):
        self.assertEqual(pages.ZONE, "shadowops.dpdns.org")
        self.assertEqual(pages.HOST, "cka.shadowops.dpdns.org")
        self.assertEqual(pages.PROJECT, "cka-simulator")
        self.assertEqual(pages.TARGET, "cka-simulator.pages.dev")

    def test_foreign_dns_fails_before_write(self):
        writes = []
        def fake(method, path, payload=None):
            if method != "GET":
                writes.append(path)
                raise AssertionError("Unexpected DNS mutation")
            if path.startswith("/zones?"):
                return 200, [{"name": pages.ZONE, "id": "test-zone"}]
            if "/dns_records?" in path:
                return 200, [{"name": pages.HOST, "type": "CNAME", "content": "other.pages.dev", "proxied": True}]
            raise AssertionError(path)
        with patch.dict(os.environ, {"CLOUDFLARE_ACCOUNT_ID": "test-account"}), patch.object(pages, "request", side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, "foreign"):
                pages.preflight()
        self.assertFalse(writes)

    def test_correct_dns_is_read_only(self):
        calls = []
        def fake(method, path, payload=None):
            calls.append(method)
            if path.startswith("/zones?"):
                return 200, [{"name": pages.ZONE, "id": "zone"}]
            if "/dns_records?" in path:
                return 200, [{"name": pages.HOST, "type": "CNAME", "content": pages.TARGET, "proxied": True}]
            raise AssertionError(path)
        with patch.dict(os.environ, {"CLOUDFLARE_ACCOUNT_ID": "test-account"}), patch.object(pages, "request", side_effect=fake):
            self.assertIsNotNone(pages.dns_record())
        self.assertEqual(set(calls), {"GET"})

    def test_github_expression_syntax_is_complete(self):
        workflow = (ROOT / ".github/workflows/cka-pages-preview.yml").read_text()
        marker = "$" + "{{"
        expressions = [line for line in workflow.splitlines() if marker in line]
        self.assertGreaterEqual(len(expressions), 8)
        for line in expressions:
            self.assertEqual(line.count(marker), line.count("}}"), line)

    def test_pipeline_uses_safe_build_and_source_guards(self):
        workflow = (ROOT / ".github/workflows/cka-pages-preview.yml").read_text()
        for text in ("npm run build:public", "npm run test:public", "cka-source/frontend/dist-public",
                     "python3 scripts/cka_pages.py preflight", "python3 scripts/cka_pages.py verify",
                     "commits/main", "cka-simulator"):
            self.assertIn(text, workflow)
        for disallowed in ("kind create", "kubectl ", "chronicles-staging", "chess-studio-staging"):
            self.assertNotIn(disallowed, workflow)


if __name__ == "__main__":
    unittest.main()
