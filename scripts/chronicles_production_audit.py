#!/usr/bin/env python3
"""Read-only daily check of the public Chronicles production release.

No user registration, credentials, Mongo writes, OCI mutations or Cloudflare writes.
Exact-SHA receipts attest successful deployments, not live API image identity.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

from chronicles_pages import probe_https, probe_react_preview
from chronicles_production_admission import verified_receipt

ORIGIN = "https://chronicles.shadowops.dpdns.org"
API = "https://chronicles-api.shadowops.dpdns.org"
SSO_JWKS = "https://api.chess-studio.shadowops.dpdns.org/api/identity/jwks"
SHA = re.compile(r"[0-9a-f]{40}")


class AuditError(RuntimeError):
    pass


def read_release() -> dict:
    url = ORIGIN + "/release.json?production_audit=1"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "User-Agent": "Mozilla/5.0 ChroniclesProductionAudit/1",
    })
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.status != 200 or response.geturl().split("?")[0] != ORIGIN + "/release.json":
            raise AuditError("unexpected public release origin")
        value = json.loads(response.read(4096))
    if not isinstance(value, dict):
        raise AuditError("malformed public release manifest")
    return value


def check_api(path: str) -> bool:
    if path not in ("health", "ready", "cors"):
        raise AuditError("invalid fixed API probe")
    url = API + ("/api/auth/login" if path == "cors" else "/api/" + path)
    headers = {"User-Agent": "ChroniclesProductionAudit/1"}
    if path == "cors":
        headers.update({
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
        })
    req = urllib.request.Request(url, headers=headers,
                                 method="OPTIONS" if path == "cors" else "GET")
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.geturl() != url or response.status not in ((200, 204) if path == "cors" else (200,)):
            return False
        if path == "cors":
            return response.headers.get("Access-Control-Allow-Origin") == ORIGIN
    return True


def check_sso_jwks() -> bool:
    """Prove the production Chess Studio issuer publishes usable public Ed25519 keys.

    This does NOT authenticate a user or test token exchange. Never log keys,
    tokens or response bodies; never fetch from staging or follow redirects.
    """
    req = urllib.request.Request(SSO_JWKS, headers={
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "User-Agent": "ChroniclesProductionAudit/1",
    })
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.status != 200 or response.geturl() != SSO_JWKS:
            return False
        body = response.read(65537)
    if len(body) > 65536:
        return False
    payload = json.loads(body)
    keys = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        return False
    trusted_kids = set()
    for key in keys:
        if not isinstance(key, dict) or "d" in key:
            return False
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            continue
        kid, x = key.get("kid"), key.get("x")
        if (not isinstance(kid, str) or not 1 <= len(kid) <= 128
            or kid in trusted_kids or not isinstance(x, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", x)
            or key.get("alg", "EdDSA") != "EdDSA"):
            return False
        raw = base64.urlsafe_b64decode(x + "=")
        if len(raw) != 32:
            return False
        trusted_kids.add(kid)
    return bool(trusted_kids)


def audit(token: str, *, manifest=read_release, page=probe_https,
          assets=probe_react_preview, api=check_api, receipt=verified_receipt,
          sso=check_sso_jwks) -> str:
    if os.environ.get("CHRONICLES_PAGES_ENV") != "production" or not token:
        raise AuditError("production environment and read token required")
    data = manifest()
    sha = data.get("build")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise AuditError("public release SHA missing or invalid")
    if page() != "ok":
        raise AuditError("public HTTPS/game shell unavailable")
    if assets(path="/", assets=b"/assets/", manifest_path=None) != "ok":
        raise AuditError("public game JS/CSS unavailable")
    for path in ("health", "ready", "cors"):
        if not api(path):
            raise AuditError("production API " + path + " failed")
    if not sso():
        raise AuditError("production SSO issuer public JWKS unavailable or invalid")
    for kind in ("production-api", "production-pages"):
        if not receipt(sha, kind, token):
            raise AuditError("no trusted " + kind + " receipt for public SHA")
    return sha


def main() -> int:
    try:
        sha = audit(os.environ.get("GH_TOKEN", ""))
    except (AuditError, urllib.error.URLError, OSError, ValueError, TypeError, TimeoutError):
        # Never echo response bodies, URLs with query strings, secrets or tokens.
        print("CHRONICLES_PRODUCTION_AUDIT_BLOCKED public readiness or evidence failed", file=sys.stderr)
        return 1
    print("CHRONICLES_PRODUCTION_READONLY_AUDIT_OK sha=" + sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
