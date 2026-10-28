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


# Explicit allowlist prevents a future uncaught provider error from appearing
# in the log even if it accidentally reaches an AuditError exception.
SAFE_AUDIT_STAGES = frozenset({
    "configuration", "manifest_read", "manifest_sha", "pages_https",
    "pages_assets", "api_health", "api_ready", "api_cors", "api_sha",
    "sso_jwks", "receipt_production_api", "receipt_production_pages",
})


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


def audit_phase(stage: str, check):
    """Return a fixed-phase result; never expose provider errors or payloads."""
    try:
        value = check()
    except Exception:
        # Even non-network evidence errors must not print HTTP bodies, tokens
        # or arbitrary GitHub / Cloudflare response strings.
        raise AuditError(stage) from None
    if not value:
        raise AuditError(stage)
    return value


def audit(token: str, *, manifest=read_release, page=probe_https,
          assets=probe_react_preview, api=check_api, receipt=verified_receipt,
          sso=check_sso_jwks, api_build=read_live_api_build) -> str:
    if os.environ.get("CHRONICLES_PAGES_ENV") != "production" or not token:
        raise AuditError("configuration")
    data = audit_phase("manifest_read", manifest)
    sha = data.get("build") if isinstance(data, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise AuditError("manifest_sha")
    audit_phase("pages_https", lambda: page() == "ok")
    audit_phase(
        "pages_assets",
        lambda: assets(path="/", assets=b"/assets/", manifest_path=None) == "ok",
    )
    for path in ("health", "ready", "cors"):
        audit_phase("api_" + path, lambda path=path: api(path))
    def same_public_build():
        runtime = api_build()
        if runtime == sha:
            return True
        # Both build IDs are public, but still sanitize untrusted API values.
        safe_runtime = (runtime if isinstance(runtime, str)
                        and SHA.fullmatch(runtime) else "unavailable")
        print(f"CHRONICLES_PRODUCTION_SHA_MISMATCH pages={sha} api={safe_runtime}",
              file=sys.stderr)
        return False

    audit_phase("api_sha", same_public_build)
    audit_phase("sso_jwks", sso)
    for kind in ("production-api", "production-pages"):
        audit_phase("receipt_" + kind.replace("-", "_"),
                    lambda kind=kind: receipt(sha, kind, token))
    return sha


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
    except AuditError as exc:
        # All audit errors originate in fixed, local stage names. No exception
        # details, response bodies, URLs, keys or tokens can reach the log.
        phase = str(exc)
        print("CHRONICLES_PRODUCTION_AUDIT_BLOCKED stage=" +
              (phase if phase in SAFE_AUDIT_STAGES else "internal"), file=sys.stderr)
        return 1
    except Exception:
        print("CHRONICLES_PRODUCTION_AUDIT_BLOCKED stage=internal", file=sys.stderr)
        return 1
    print("CHRONICLES_PRODUCTION_READONLY_AUDIT_OK sha=" + sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
