#!/usr/bin/env python3
"""Read-only daily check of the public Chronicles production release.

No user registration, credentials, Mongo writes, OCI mutations or Cloudflare writes.
Exact-SHA receipts attest successful deployments, not live API image identity.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from chronicles_pages import probe_https, probe_react_preview
from chronicles_production_admission import verified_receipt

ORIGIN = "https://chronicles.shadowops.dpdns.org"
API = "https://chronicles-api.shadowops.dpdns.org"
SHA = re.compile(r"[0-9a-f]{40}\\Z")


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


def audit(token: str, *, manifest=read_release, page=probe_https,
          assets=probe_react_preview, api=check_api, receipt=verified_receipt) -> str:
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
