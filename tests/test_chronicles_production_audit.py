"""Read-only production smoke gates; every test runs without external traffic."""
import base64
import io
import json
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
                receipt=None, sso=True, api_build=SHA,
                token="read-token", env="production"):
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
                sso=lambda: calls.append("sso-jwks") or sso,
                api_build=lambda: calls.append("api-build") or api_build,
            )
        return result, calls

    def test_good_sha_requires_public_https_assets_api_cors_and_both_receipts(self):
        sha, calls = self.checked()
        self.assertEqual(sha, SHA)
        self.assertEqual(calls, [
            "health", "ready", "cors", "api-build", "sso-jwks",
            "production-api", "production-pages",
        ])

    def test_fail_closed_for_bad_manifest_or_public_resources(self):
        for kwargs in (
            {"manifest": {}},
            {"manifest": {"build": "not-a-sha"}},
            {"manifest": {"build": "B" * 40}},
            {"page": "tls_error"},
            {"assets": "unexpected_content"},
            {"api": lambda path: path != "cors"},
            {"api_build": None},
            {"api_build": "b" * 40},
            {"sso": False},
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

    def test_runtime_api_release_requires_exact_fixed_production_origin_and_sha(self):
        url = audit.API_RELEASE
        self.assertEqual(url, "https://chronicles-api.shadowops.dpdns.org/api/release")
        payload = ('{"release":"v1","build":"' + SHA + '"}').encode()
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(url, data=payload)) as opener:
            self.assertEqual(audit.read_live_api_build(), SHA)
            request = opener.call_args.args[0]
            self.assertTrue(request.full_url.startswith(url + "?production_sha_check="))
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("Cookie"))
        for response in (
            Response("https://evil.example/release", data=payload),
            Response(url, status=503, data=payload),
            Response(url, data=b"{}"),
            Response(url, data=b'{"build":"invalid"}'),
            Response(url, data=b'{"build":42}'),
            Response(url, data=b'[]'),
            Response(url, data=b'not-json'),
            Response(url, data=b" " * 4097),
        ):
            with self.subTest(url=response.url, size=len(response.data)):
                with patch.object(audit.urllib.request, "urlopen", return_value=response):
                    self.assertIsNone(audit.read_live_api_build())
        with patch.object(audit.urllib.request, "urlopen",
                          side_effect=TimeoutError):
            self.assertIsNone(audit.read_live_api_build())

    def test_pages_production_guard_requires_exact_runtime_sha_without_secrets(self):
        self.assertTrue(audit.verify_api_source(SHA, read=lambda: SHA))
        for provided in ("bad", "A" * 40, "", "b" * 40):
            with self.subTest(provided=provided):
                self.assertFalse(audit.verify_api_source(
                    provided, read=lambda: SHA))
        self.assertFalse(audit.verify_api_source(SHA, read=lambda: None))
        self.assertFalse(audit.verify_api_source(SHA, read=lambda: "b" * 40))
        # The CLI's sole network operation is reading a public endpoint, not
        # calling GitHub, OCI, Cloudflare or any player mutation endpoint.
        with patch.object(audit.sys, "argv", ["audit", "--verify-api-sha", SHA]), \
             patch.dict(os.environ, {"CHRONICLES_PAGES_ENV": "production"}, clear=True), \
             patch.object(audit, "verify_api_source", return_value=True) as gate, \
             patch.object(audit, "audit") as full:
            self.assertEqual(audit.main(), 0)
            gate.assert_called_once_with(SHA)
            full.assert_not_called()
        with patch.object(audit.sys, "argv", ["audit", "--verify-api-sha", SHA]), \
             patch.dict(os.environ, {"CHRONICLES_PAGES_ENV": "production"}, clear=True), \
             patch.object(audit, "verify_api_source", return_value=False):
            self.assertEqual(audit.main(), 1)
        with patch.object(audit.sys, "argv", ["audit", "--verify-api-sha", SHA]), \
             patch.dict(os.environ, {"CHRONICLES_PAGES_ENV": "staging"}, clear=True), \
             patch.object(audit, "verify_api_source") as gate:
            self.assertEqual(audit.main(), 1)
            gate.assert_not_called()

    def test_daily_audit_uses_madrid_wall_clock_and_follows_train(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-production-audit.yml").read_text()
        self.assertIn("workflow_run:", workflow)
        self.assertIn("workflows: ['Chronicles production · release train']", workflow)
        self.assertIn("types: [completed]", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("cron: '15 9 * * *'", workflow)
        self.assertIn("timezone: Europe/Madrid", workflow)
        self.assertNotIn("cron: '23 6 * * *'", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertNotIn("actions: write", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertIn("github.event_name != 'pull_request'", workflow)
        self.assertIn("scripts/chronicles_production_audit.py", workflow)

    def test_production_sso_issuer_jwks_public_ed25519_only(self):
        url = audit.SSO_JWKS
        self.assertEqual(
            url, "https://api.chess-studio.shadowops.dpdns.org/api/identity/jwks")
        x = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
        good = {"keys": [{"kty": "OKP", "crv": "Ed25519",
                          "kid": "prod-current", "alg": "EdDSA", "x": x}]}
        def fake(payload, *, status=200, redirect=None):
            return Response(redirect or url, status=status,
                            data=json.dumps(payload).encode())

        with patch.object(audit.urllib.request, "urlopen",
                          return_value=fake(good)) as opener:
            self.assertTrue(audit.check_sso_jwks())
            req = opener.call_args.args[0]
            self.assertEqual(req.full_url, url)
            self.assertEqual(req.get_method(), "GET")
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Cookie"))

        invalid = (
            {"keys": []},
            {"keys": [{"kty": "RSA", "kid": "rsa", "n": "xxx"}]},
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "bad", "x": "?"}]},
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "", "x": x}]},
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "secret",
                        "x": x, "d": "private-leak"}]},
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "bad-alg",
                        "x": x, "alg": "HS256"}]},
            {"keys": [good["keys"][0], dict(good["keys"][0])]},
            {"keys": "not-an-array"},
            {"message": "not a JWKS"},
        )
        for payload in invalid:
            with self.subTest(payload=str(payload)[:60]), patch.object(
                audit.urllib.request, "urlopen", return_value=fake(payload)
            ):
                self.assertFalse(audit.check_sso_jwks())
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=fake(good, redirect="https://other.example/jwks")):
            self.assertFalse(audit.check_sso_jwks())
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=fake(good, status=302)):
            self.assertFalse(audit.check_sso_jwks())
        with patch.object(audit.urllib.request, "urlopen",
                          return_value=Response(url, data=b" " * 65537)):
            self.assertFalse(audit.check_sso_jwks())

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
