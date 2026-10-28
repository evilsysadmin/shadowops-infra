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
import time
import urllib.error
import urllib.request

from chronicles_pages import probe_https, probe_react_preview
from chronicles_production_admission import verified_receipt

ORIGIN = "https://chronicles.shadowops.dpdns.org"
API = "https://chronicles-api.shadowops.dpdns.org"
API_RELEASE = API + "/api/release"
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


def read_live_api_build() -> str | None:
    """Read the API's runtime source SHA, not the historical image receipt.

    Fixed public production URL; malformed/unavailable/redirected identity
    fails closed. No secrets, user accounts or data writes.
    """
    req = urllib.request.Request(
        API_RELEASE + "?production_sha_check=" + str(time.time_ns()),
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": "ChroniclesProductionAudit/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200 or response.geturl().partition("?")[0] != API_RELEASE:
                return None
            raw = response.read(4097)
        if len(raw) > 4096:
            return None
        payload = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(payload, dict):
        return None
    build = payload.get("build")
    return build if isinstance(build, str) and SHA.fullmatch(build) else None


def verify_api_source(expected_sha: str, *, read=read_live_api_build) -> bool:
    """Read-only pre-publish gate, used independently of release train."""
    return (isinstance(expected_sha, str)
            and SHA.fullmatch(expected_sha) is not None
            and read() == expected_sha)


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
          sso=check_sso_jwks, api_build=read_live_api_build) -> str:
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
    runtime_build = api_build()
    if runtime_build != sha:
        # Both values are public source identities, not API responses/tokens.
        # Sanitize even mocks or compromised responses before logging.
        safe_runtime = (runtime_build if isinstance(runtime_build, str)
                        and SHA.fullmatch(runtime_build) else "unavailable")
        print(f"CHRONICLES_PRODUCTION_SHA_MISMATCH pages={sha} api={safe_runtime}",
              file=sys.stderr)
        raise AuditError("production API public source SHA missing or mismatched")
    if not sso():
        raise AuditError("production SSO issuer public JWKS unavailable or invalid")
    for kind in ("production-api", "production-pages"):
        if not receipt(sha, kind, token):
            raise AuditError("no trusted " + kind + " receipt for public SHA")
    return sha


# Closed vocabulary for operators: no untrusted exception text, URLs or secrets.
AUDIT_FAILURE_REASONS = {
    "production environment and read token required": "AUDIT_CONTEXT_INVALID",
    "unexpected public release origin": "PAGES_MANIFEST_UNAVAILABLE",
    "malformed public release manifest": "PAGES_MANIFEST_INVALID",
    "public release SHA missing or invalid": "PAGES_BUILD_INVALID",
    "public HTTPS/game shell unavailable": "PAGES_SHELL_DOWN",
    "public game JS/CSS unavailable": "PAGES_ASSETS_DOWN",
    "production API health failed": "API_HEALTH_DOWN",
    "production API ready failed": "API_READY_DOWN",
    "production API cors failed": "API_CORS_FAILED",
    "production API public source SHA missing or mismatched": "API_PAGES_SHA_MISMATCH",
    "production SSO issuer public JWKS unavailable or invalid": "SSO_JWKS_UNAVAILABLE",
    "no trusted production-api receipt for public SHA": "API_RECEIPT_MISSING",
    "no trusted production-pages receipt for public SHA": "PAGES_RECEIPT_MISSING",
}


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-api-sha":
        if (os.environ.get("CHRONICLES_PAGES_ENV") != "production"
                or not verify_api_source(sys.argv[2])):
            print("CHRONICLES_PRODUCTION_API_SOURCE_BLOCKED", file=sys.stderr)
            return 1
        print("CHRONICLES_PRODUCTION_API_SOURCE_OK sha=" + sys.argv[2])
        return 0
    if len(sys.argv) != 1:
        return 64
    try:
        sha = audit(os.environ.get("GH_TOKEN", ""))
    except (AuditError, urllib.error.URLError, OSError, ValueError, TypeError, TimeoutError) as exc:
        # Fixed reason codes only. Never echo provider errors, URLs, bodies or tokens.
        reason = (AUDIT_FAILURE_REASONS.get(str(exc), "EVIDENCE_UNAVAILABLE")
                  if isinstance(exc, AuditError) else "EVIDENCE_UNAVAILABLE")
        print("CHRONICLES_PRODUCTION_AUDIT_BLOCKED reason=" + reason, file=sys.stderr)
        return 1
    print("CHRONICLES_PRODUCTION_READONLY_AUDIT_OK sha=" + sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
