"""Never mistake a staging login or a bare JWKS for production Bridge Squad SSO."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
import io

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_prod_identity_probe as probe

JWKS = json.dumps({"keys": [{
    "kty": "OKP", "crv": "Ed25519", "use": "sig",
    "kid": "production-key", "x": "A" * 43,
}]}).encode()
RETURN = (probe.ORIGIN + "/?shadowops=central").encode()
LOGIN = (
    b'<html><body data-return-url="' + RETURN + b'"><h1>Bridge Squad</h1>'
    b'<a class="brand" href="' + RETURN + b'">SHADOWOPS</a>'
    b'<a class="return-link" href="' + RETURN + b'">Volver a Bridge Squad</a>'
    b'</body></html>'
)
CSP = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"


def reader(states=None):
    responses = {
        probe.ISSUER + "/readyz": (200, {}, b"ready"),
        probe.ISSUER + "/api/identity/jwks": (
            200, {"Content-Type": "application/json"}, JWKS),
        probe.ISSUER + "/login?app=bridgesquad": (
            200, {"Content-Type": "text/html; charset=utf-8",
                  "Content-Security-Policy": CSP}, LOGIN),
    }
    responses.update(states or {})
    return lambda url: responses[url]


class BridgeSquadProductionIdentityTests(unittest.TestCase):
    def test_public_surface_pass_still_does_not_prove_real_authentication(self):
        value = probe.inspect(reader())
        self.assertEqual(value, {
            "service": "present", "jwks": "present", "login": "present",
            "public_surface": "present", "service_proof": "not-verified",
            "token_issuance": "not-verified", "authorization": "not-verified",
        })

    def test_absent_dns_or_issuer_produces_explicit_not_ready(self):
        value = probe.inspect(reader({
            probe.ISSUER + path: (0, {}, b"") for path in probe.ROUTES
        }))
        self.assertEqual(value["public_surface"], "not-ready")
        self.assertTrue(all(value[key] == "unavailable" for key in ("service", "jwks", "login")))

    def test_partial_issuer_still_blocks_production_launch(self):
        for endpoint in probe.ROUTES:
            for status in (0, 404, 502, 503, 504):
                path = probe.ISSUER + endpoint
                v = probe.inspect(reader({path: (status, {}, b"")}))
                with self.subTest(path=path, status=status):
                    self.assertEqual(v["public_surface"], "not-ready")

    def test_redirects_fail_not_followed_to_staging(self):
        for endpoint in probe.ROUTES:
            path = probe.ISSUER + endpoint
            with self.subTest(path=path), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (
                    302, {"Location": "https://id-staging.shadowops.dpdns.org/login"}, b"",
                )}))

    def test_wrong_origin_or_login_csp_cannot_admit(self):
        for payload in (
            LOGIN.replace(probe.ORIGIN.encode(), b"https://staging.bridgesquad.shadowops.dpdns.org"),
            LOGIN.replace(b"Bridge Squad", b"Snooker"),
            LOGIN + b"id-staging.shadowops.dpdns.org",
        ):
            path = probe.ISSUER + "/login?app=bridgesquad"
            with self.subTest(payload=payload[:50]), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (200, {
                    "Content-Type": "text/html", "Content-Security-Policy": CSP}, payload)}))
        path = probe.ISSUER + "/login?app=bridgesquad"
        with self.assertRaises(probe.UnsafeIssuer):
            probe.inspect(reader({path: (200, {"Content-Type": "text/html"}, LOGIN)}))

    def test_malicious_return_link_cannot_hide_behind_valid_url_text(self):
        path = probe.ISSUER + "/login?app=bridgesquad"
        for injection in (
            LOGIN.replace(b'class="return-link" href="' + RETURN,
                          b'class="return-link" href="https://id-staging.shadowops.dpdns.org/'),
            LOGIN.replace(b'data-return-url="' + RETURN, b'data-return-url="https://evil.test/'),
            LOGIN + b'<p>' + RETURN + b'</p><a class="brand" href="https://evil.test/">bad</a>',
        ):
            with self.subTest(injection=injection[:70]), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (200, {
                    "Content-Type": "text/html", "Content-Security-Policy": CSP}, injection)}))

    def test_no_dangerous_jwks(self):
        for item in (
            {"keys": []},
            {"keys": [{"kty": "RSA", "crv": "Ed25519", "use": "sig", "kid": "x", "x": "A"*43}]},
            {"keys": [{**json.loads(JWKS)["keys"][0], "d": "private"}]},
            {"keys": [json.loads(JWKS)["keys"][0]]*2},
            {"keys": "unknown"},
        ):
            path = probe.ISSUER + "/api/identity/jwks"
            with self.subTest(item=item), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (
                    200, {"Content-Type": "application/json"}, json.dumps(item).encode()
                )}))

    def test_public_probe_does_not_accept_cookie_set_or_html_keyset(self):
        path = probe.ISSUER + "/api/identity/jwks"
        for headers in (
            {"Content-Type": "text/html"},
            {"Content-Type": "application/json", "Set-Cookie": "shadowops_session=bad"},
        ):
            with self.subTest(headers=headers), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (200, headers, JWKS)}))

    def test_overly_large_and_401_or_403_fail_closed(self):
        path = probe.ISSUER + "/login?app=bridgesquad"
        for status, body in (
            (200, b"a" * (probe.MAX_RESPONSE + 1)), (401, b""), (403, b""),
        ):
            with self.subTest(status=status), self.assertRaises(probe.UnsafeIssuer):
                probe.inspect(reader({path: (status, {}, body)}))

    def test_only_three_exact_public_get_targets_are_allowed(self):
        self.assertEqual(probe.ROUTES, (
            "/readyz", "/api/identity/jwks", "/login?app=bridgesquad"))
        for suffix in ("/api/identity/token", "/api/identity/freshness",
                       "/api/identity/login", "/api/identity/signup"):
            with self.subTest(suffix=suffix), self.assertRaises(probe.UnsafeIssuer):
                probe.read_public(probe.ISSUER + suffix)
        with self.assertRaises(probe.UnsafeIssuer):
            probe.read_public("https://id-staging.shadowops.dpdns.org/login?app=bridgesquad")

    def test_https_failure_is_not_misreported_as_200(self):
        url = probe.ISSUER + "/readyz"
        with mock.patch.object(probe.urllib.request, "build_opener") as patched:
            patched.return_value.open.side_effect = probe.urllib.error.URLError("DNS missing")
            self.assertEqual(probe.read_public(url), (0, {}, b""))
            patched.return_value.open.side_effect = HTTPError(url, 503, "unavailable", {}, io.BytesIO(b""))
            self.assertEqual(probe.read_public(url)[0], 503)


if __name__ == "__main__":
    unittest.main()
