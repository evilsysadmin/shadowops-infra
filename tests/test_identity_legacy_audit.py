"""Offline tests only: no external endpoints or GitHub secrets needed."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("identity_legacy_audit", ROOT / "scripts" / "identity_legacy_audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def jwks(byte: int, *, kid="kid-1", **extra) -> dict:
    return {"keys": [{
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
        "x": base64.urlsafe_b64encode(bytes([byte] * 32)).decode().rstrip("="),
        **extra,
    }]}


class MockResponse:
    status = 200
    def __init__(self, url, data):
        self._url, self._data = url, data
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def geturl(self):
        return self._url
    def read(self, _size):
        return self._data


class IdentityLegacyAuditTests(unittest.TestCase):
    def test_fixed_legacy_hosts_are_different_and_read_only(self):
        self.assertEqual(audit.LEGACY_ISSUERS["staging"], "https://api-staging.chess-studio.shadowops.dpdns.org")
        self.assertEqual(audit.LEGACY_ISSUERS["production"], "https://api.chess-studio.shadowops.dpdns.org")
        self.assertEqual(audit.JWKS_PATH, "/api/identity/jwks")

    def test_valid_ed25519_public_jwk(self):
        value = audit.parse_keys(jwks(1))
        self.assertEqual(len(value), 1)
        self.assertEqual(len(next(iter(value))), 64)

    def test_same_public_key_between_environments_fails_closed(self):
        with self.assertRaisesRegex(audit.AuditError, "overlapping"):
            audit.audit(fetch=lambda _issuer: audit.parse_keys(jwks(7)))

    def test_different_public_keys_between_environments_succeed(self):
        stage = audit.LEGACY_ISSUERS["staging"]
        self.assertEqual(
            audit.audit(fetch=lambda issuer: audit.parse_keys(jwks(3 if issuer == stage else 9))),
            {"staging": 1, "production": 1},
        )

    def test_malformed_and_private_keys_are_rejected(self):
        cases = [
            {}, {"keys": []}, {"keys": None},
            jwks(1, d="should-never-be-public"),
            jwks(1, alg="none"), jwks(1, use="enc"),
            jwks(1, kty="RSA"), jwks(1, crv="P-256"),
            jwks(1, x="x"), jwks(1, kid=""),
            {"keys": jwks(1)["keys"] + jwks(2)["keys"]},
            {"keys": jwks(1)["keys"] + jwks(1, kid="second")["keys"]},
        ]
        for value in cases:
            with self.subTest(value=str(value)[:90]), self.assertRaises(audit.AuditError):
                audit.parse_keys(value)

    def test_redirect_to_other_origin_is_rejected(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 12)
            return MockResponse("https://evil.invalid/api/identity/jwks", json.dumps(jwks(1)).encode())
        with self.assertRaisesRegex(audit.AuditError, "redirected"):
            audit.fetch_keys(audit.LEGACY_ISSUERS["staging"], opener=opener)

    def test_valid_https_response_from_exact_issuer(self):
        issuer = audit.LEGACY_ISSUERS["staging"]
        def opener(request, timeout):
            self.assertEqual(request.full_url, issuer + audit.JWKS_PATH)
            return MockResponse(request.full_url, json.dumps(jwks(1)).encode())
        self.assertEqual(len(audit.fetch_keys(issuer, opener=opener)), 1)

    def test_invalid_json_is_rejected(self):
        issuer = audit.LEGACY_ISSUERS["production"]
        with self.assertRaisesRegex(audit.AuditError, "not valid JSON"):
            audit.fetch_keys(issuer, opener=lambda request, timeout: MockResponse(request.full_url, b"{invalid"))
