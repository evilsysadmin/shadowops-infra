#!/usr/bin/env python3
"""Public-only evidence for isolated production ShadowOps ID Bridge Squad readiness.

Never sends credentials, cookies, POSTs, secrets or login data. A green
inspection alone is NOT a production sign-in or a Pages activation receipt.
"""
from __future__ import annotations

import json
from html.parser import HTMLParser
import sys
import urllib.error
import urllib.request

ISSUER = "https://id.shadowops.dpdns.org"
ORIGIN = "https://bridgesquad.shadowops.dpdns.org"
ROUTES = ("/readyz", "/api/identity/jwks", "/login?app=bridgesquad")
MAX_RESPONSE = 65_536


class UnsafeIssuer(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_public(url: str) -> tuple[int, dict, bytes]:
    if url not in tuple(ISSUER + path for path in ROUTES):
        raise UnsafeIssuer("Only exact production Identity probe paths are allowed")
    request = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json, text/html", "User-Agent": "ShadowOps-BridgeSquad-ProductionIdP-Audit/1.0",
    })
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            return response.status, dict(response.headers), response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(MAX_RESPONSE + 1)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, {}, b""


def _headers(headers: dict, *, html: bool) -> None:
    content_type = str(headers.get("Content-Type", headers.get("content-type", ""))).lower()
    if not content_type.startswith("text/html" if html else "application/json"):
        raise UnsafeIssuer("Unexpected Identity response media type")
    if headers.get("Set-Cookie") or headers.get("set-cookie"):
        raise UnsafeIssuer("Public GET identity probe must never set session cookies")


def _jwks(body: bytes) -> None:
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise UnsafeIssuer("Unparseable production public keys") from None
    if not isinstance(data, dict) or set(data) != {"keys"} or not isinstance(data["keys"], list) \
            or not 1 <= len(data["keys"]) <= 20:
        raise UnsafeIssuer("Missing production verification keys")
    kids = set()
    for key in data["keys"]:
        if not isinstance(key, dict) or key.get("kty") != "OKP" \
                or key.get("crv") != "Ed25519" or key.get("use") != "sig" \
                or "d" in key or not isinstance(key.get("x"), str) \
                or not isinstance(key.get("kid"), str) or not 1 <= len(key["kid"]) <= 128:
            raise UnsafeIssuer("Invalid production JWKS contract")
        if key["kid"] in kids:
            raise UnsafeIssuer("Duplicate production signing key ID")
        kids.add(key["kid"])


class LoginReturns(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.body_returns = []
        self.links = []
        self.application_seen = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "body":
            self.body_returns.append(attrs.get("data-return-url"))
        if tag == "a" and attrs.get("class") in ("brand", "return-link"):
            self.links.append((attrs.get("class"), attrs.get("href")))


def _login(body: bytes, headers: dict) -> None:
    try:
        html = body.decode("utf-8")
    except UnicodeError:
        raise UnsafeIssuer("Production login page is not UTF-8") from None
    canonical_return = ORIGIN + "/?shadowops=central"
    document = LoginReturns()
    try:
        document.feed(html)
        document.close()
    except ValueError:
        raise UnsafeIssuer("Production login page invalid HTML") from None
    # Staging and production must never share login return destinations.
    # Validate exact HTML attributes, not a substring of arbitrary page text.
    if (document.body_returns != [canonical_return]
            or sorted(document.links) != sorted([
                ("brand", canonical_return), ("return-link", canonical_return)
            ]) or "Bridge Squad" not in html):
        raise UnsafeIssuer("Production login audience or return origin not pinned")
    csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
    if "default-src 'none'" not in csp or "form-action 'self'" not in csp:
        raise UnsafeIssuer("Production login page CSP missing")


def inspect(reader=read_public) -> dict[str, str]:
    evidence: dict[str, str] = {}
    for label, route in (("service", ROUTES[0]), ("jwks", ROUTES[1]), ("login", ROUTES[2])):
        status, headers, body = reader(ISSUER + route)
        if type(status) is not int or not isinstance(headers, dict) \
                or not isinstance(body, bytes) or len(body) > MAX_RESPONSE:
            raise UnsafeIssuer("Invalid or oversized production Identity response")
        if 300 <= status < 400:
            raise UnsafeIssuer("Identity public endpoint redirects unexpectedly")
        if status == 200:
            if label != "service":
                _headers(headers, html=(label == "login"))
                (_jwks(body) if label == "jwks" else _login(body, headers))
            evidence[label] = "present"
        elif status in (0, 404, 503, 502, 504):
            evidence[label] = "unavailable"
        else:
            raise UnsafeIssuer("Unexpected production Identity endpoint response")
    evidence["public_surface"] = (
        "present" if all(evidence[k] == "present" for k in ("service", "jwks", "login"))
        else "not-ready"
    )
    # Even a valid public page cannot establish actual token issuance,
    # private Vault service proof, freshness/revocation, or a signed-in user.
    evidence["service_proof"] = "not-verified"
    evidence["token_issuance"] = "not-verified"
    evidence["authorization"] = "not-verified"
    return evidence


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("inspect", "require-public-surface"):
        print("Usage: bridgesquad_prod_identity_probe.py inspect|require-public-surface", file=sys.stderr)
        return 2
    try:
        receipt = inspect()
    except UnsafeIssuer as exc:
        print("BRIDGESQUAD_PROD_IDENTITY_UNSAFE reason=" + type(exc).__name__, file=sys.stderr)
        return 1
    print("BRIDGESQUAD_PROD_IDENTITY_PUBLIC " + " ".join(
        f"{key}={value}" for key, value in receipt.items()
    ))
    if argv[1] == "require-public-surface" and receipt["public_surface"] != "present":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
