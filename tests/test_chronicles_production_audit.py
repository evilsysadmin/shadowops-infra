"""Read-only production smoke gates; every test runs without external traffic."""
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_production_audit as audit

SHA = "a" * 40


class Response:
    def __init__(self, url, status=200, data=b"{}", headers=None):
        self.url, self.status, self.data = url, status, data
        self.headers = headers or {}

    def geturl(self):
        return self.url

    def read(self, count=-1):
        return self.data if count < 0 else self.data[:count]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ProductionAuditTests(unittest.TestCase):
    def checked(self, *, manifest=None, page="ok", assets="ok", api=None,
                receipt=None, token="read-token", env="production"):
        calls = []
        def api_probe(name):
            calls.append(name)
            return True if api is None else api(name)

        def receipt_probe(sha, kind, supplied):
            calls.append(kind)
            self.assertEqual(supplied, token)
            self.assertEqual(sha, SHA)
            return True if receipt is None else receipt(kind)

        with patch.dict(os.environ, {"CHRONICLES_PAGES_ENV": env}):
            result = audit.audit(
                token, manifest=lambda: {"build": SHA} if manifest is None else manifest,
                page=lambda: page,
                assets=lambda **kwargs: assets,
                api=api_probe, receipt=receipt_probe,
            )
        return result, calls

    def test_good_sha_requires_public_https_assets_api_cors_and_both_receipts(self):
        sha, calls = self.checked()
        self.assertEqual(sha, SHA)
        self.assertEqual(calls, [
            "health", "ready", "cors", "production-api", "production-pages",
        ])

    def test_fail_closed_for_bad_manifest_or_public_resources(self):
        for kwargs in (
            {"manifest": {}},
            {"manifest": {"build": "not-a-sha"}},
            {"manifest": {"build": "B" * 40}},
            {"page": "tls_error"},
            {"assets": "unexpected_content"},
            {"api": lambda path: path != "cors"},
            {"receipt": lambda kind: kind != "production-api"},
            {"receipt": lambda kind: kind != "production-pages"},
            {"token": ""},
            {"env": "staging"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(audit.AuditError):
                    self.checked(**kwargs)

    def test_public_manifest_origin_is_fixed(self):
        url = audit.ORIGIN + "/release.json?production_audit=1"
        payload = ('{"release":"v1","build":"' + SHA + '"}').encode()
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(url, data=payload)) as opener:
            self.assertEqual(audit.read_release()["build"], SHA)
            self.assertEqual(opener.call_args.args[0].full_url, url)
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response("https://example.com/release.json", data=payload)):
            with self.assertRaises(audit.AuditError):
                audit.read_release()

    def test_api_checks_are_get_only_except_cors_options(self):
        url = audit.API + "/api/health"
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(url)) as opener:
            self.assertTrue(audit.check_api("health"))
            self.assertEqual(opener.call_args.args[0].get_method(), "GET")
        cors_url = audit.API + "/api/auth/login"
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(cors_url, status=204,
                          headers={"Access-Control-Allow-Origin": audit.ORIGIN})) as opener:
            self.assertTrue(audit.check_api("cors"))
            req = opener.call_args.args[0]
            self.assertEqual(req.get_method(), "OPTIONS")
            self.assertEqual(req.get_header("Origin"), audit.ORIGIN)
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(cors_url, status=204, headers={})):
            self.assertFalse(audit.check_api("cors"))
        with self.assertRaises(audit.AuditError):
            audit.check_api("create-account")


if __name__ == "__main__":
    unittest.main()
