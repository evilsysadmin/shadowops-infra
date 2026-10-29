#!/usr/bin/env python3
"""Read-only audit of current Chess Studio IdP public JWKS per environment.

This verifies *published public key separation*, NOT overall IdP health,
login correctness, cryptographic token validation or a new Identity deployment.
No cookies, credentials, accounts, mutations, DNS updates or secrets.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

LEGACY_ISSUERS = {
    "staging": "https://api-staging.chess-studio.shadowops.dpdns.org",
    "production": "https://api.chess-studio.shadowops.dpdns.org",
}
JWKS_PATH = "/api/identity/jwks"
MAX_BODY = 64 * 1024


class AuditError(RuntimeError):
    pass


def parse_keys(value: object) -> frozenset[str]:
    if not isinstance(value, dict):
        raise AuditError("JWKS must be a JSON object")
    entries = value.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 20:
        raise AuditError("JWKS must contain 1..20 public keys")
    fingerprints: set[str] = set()
    kids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise AuditError("Invalid JWKS key")
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            raise AuditError("JWKS contains a key other than Ed25519")
        if entry.get("alg") != "EdDSA" or entry.get("use") != "sig":
            raise AuditError("JWKS signing algorithm or intended use is invalid")
        if "d" in entry:
            raise AuditError("Private JWK material exposed")
        kid = entry.get("kid")
        encoded = entry.get("x")
        if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
            raise AuditError("Signing key id is missing/invalid")
        if kid in kids:
            raise AuditError("Duplicate signing key id")
        kids.add(kid)
        if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
            raise AuditError("Malformed Ed25519 public key encoding")
        try:
            public = base64.urlsafe_b64decode(encoded + "=")
        except Exception as exc:
            raise AuditError("Malformed Ed25519 public key") from exc
        if len(public) != 32:
            raise AuditError("Wrong public key length")
        fingerprints.add(hashlib.sha256(public).hexdigest())
    if len(fingerprints) != len(entries):
        raise AuditError("Duplicate signing key")
    return frozenset(fingerprints)


def fetch_keys(issuer: str, *, opener=urlopen) -> frozenset[str]:
    parsed = urlsplit(issuer)
    if parsed.scheme != "https" or not parsed.hostname or parsed.port or parsed.path or parsed.query:
        raise AuditError("Issuer must be a strict HTTPS origin")
    request = Request(issuer + JWKS_PATH, headers={
        "Accept": "application/json",
        "User-Agent": "ShadowOps-Legacy-JWKS-Audit/1",
    })
    try:
        with opener(request, timeout=12) as response:
            target = urlsplit(response.geturl())
            if target.scheme != "https" or target.hostname != parsed.hostname or target.port:
                raise AuditError("JWKS redirected to another origin")
            if response.status != 200:
                raise AuditError("JWKS returned non-200")
            raw = response.read(MAX_BODY + 1)
    except (OSError, TimeoutError) as exc:
        raise AuditError("Could not fetch JWKS over HTTPS") from exc
    if len(raw) > MAX_BODY:
        raise AuditError("JWKS exceeds 64 KiB")
    try:
        return parse_keys(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError("JWKS is not valid JSON") from exc


def audit(fetch=fetch_keys) -> dict[str, int]:
    keys: dict[str, frozenset[str]] = {}
    for environment, issuer in LEGACY_ISSUERS.items():
        keys[environment] = fetch(issuer)
    if keys["staging"] & keys["production"]:
        raise AuditError("Staging and production expose overlapping signing keys")
    return {name: len(value) for name, value in keys.items()}


def main() -> int:
    try:
        counts = audit()
    except AuditError as exc:
        print("SHADOWOPS_LEGACY_JWKS_AUDIT_FAILED: " + str(exc), file=sys.stderr)
        return 1
    print("SHADOWOPS_LEGACY_JWKS_SEPARATION_OK staging_keys={staging} production_keys={production}".format(**counts))
    print("This checks only the legacy IdP's public JWKS. Identity extraction is NOT deployed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
