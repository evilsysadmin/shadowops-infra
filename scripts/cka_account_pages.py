#!/usr/bin/env python3
"""Dedicated CKA static-preview Pages owner; no Kubernetes, OCI or tunnel operations."""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
HOST = "staging.cka.shadowops.dpdns.org"
PROJECT = "cka-account-staging"
TARGET = PROJECT + ".pages.dev"


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError("Missing Cloudflare secret: " + name)
    return value


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API + path, method=method, data=body, headers={
        "Authorization": "Bearer " + required("CLOUDFLARE_API_TOKEN"),
        "Content-Type": "application/json", "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=18) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        decoded = json.loads(raw) if raw else {}
    except (ValueError, UnicodeError):
        raise RuntimeError(f"Cloudflare {method} returned invalid JSON (HTTP {status})") from None
    if (status not in (200, 201, 404) or
            (status != 404 and (not isinstance(decoded, dict) or decoded.get("success") is not True))):
        raise RuntimeError(f"Cloudflare {method} rejected request (HTTP {status})")
    return status, decoded.get("result") if isinstance(decoded, dict) else None


def project_path() -> str:
    return "/accounts/" + required("CLOUDFLARE_ACCOUNT_ID") + "/pages/projects/" + PROJECT


def domain_path() -> str:
    return project_path() + "/domains/" + urllib.parse.quote(HOST, safe="")


def zone_id() -> str:
    query = urllib.parse.urlencode({"name": ZONE, "account.id": required("CLOUDFLARE_ACCOUNT_ID")})
    status, zones = request("GET", "/zones?" + query)
    if status != 200 or not isinstance(zones, list):
        raise RuntimeError("Cannot inspect Cloudflare DNS zone")
    matches = [zone for zone in zones if isinstance(zone, dict) and zone.get("name") == ZONE and zone.get("id")]
    if len(matches) != 1:
        raise RuntimeError("Cloudflare DNS zone identity is ambiguous")
    return str(matches[0]["id"])


def dns_path() -> str:
    return "/zones/" + zone_id() + "/dns_records"


def dns_record() -> dict | None:
    status, rows = request("GET", dns_path() + "?" + urllib.parse.urlencode({"name": HOST}))
    if status != 200 or not isinstance(rows, list):
        raise RuntimeError("Cannot inspect CKA DNS")
    matching = [row for row in rows if isinstance(row, dict) and row.get("name") == HOST]
    if len(matching) > 1:
        raise RuntimeError("Ambiguous CKA DNS: multiple records")
    if matching:
        record = matching[0]
        if (record.get("type") != "CNAME" or record.get("proxied") is not True
                or str(record.get("content", "")).rstrip(".") != TARGET):
            raise RuntimeError("Refusing to overwrite an existing foreign CKA DNS record")
        return record
    return None


def existing_project() -> bool:
    status, project = request("GET", project_path())
    if status == 404:
        return False
    if status != 200 or not isinstance(project, dict):
        raise RuntimeError("Cannot inspect CKA Pages project")
    if project.get("name") != PROJECT or project.get("production_branch") != "main":
        raise RuntimeError("Unexpected CKA Pages project identity or branch")
    return True


def preflight() -> None:
    dns_record()
    exists = existing_project()
    if exists:
        status, domain = request("GET", domain_path())
        if status == 200 and (
            not isinstance(domain, dict) or domain.get("name") != HOST
            or domain.get("status") in ("blocked", "deactivated", "error")
        ):
            raise RuntimeError("Unexpected existing CKA Pages domain")
        if status not in (200, 404):
            raise RuntimeError("Unable to inspect CKA Pages domain")
    print("CKA_PAGES_OWNERSHIP_PREFLIGHT_OK " + HOST)


def ensure_project() -> None:
    if not existing_project():
        status, created = request("POST", "/accounts/" + required("CLOUDFLARE_ACCOUNT_ID") + "/pages/projects", {
            "name": PROJECT, "production_branch": "main",
        })
        if status not in (200, 201) or not isinstance(created, dict) or created.get("name") != PROJECT:
            raise RuntimeError("Failed to create dedicated CKA Pages project")
    if not existing_project():
        raise RuntimeError("Pages project did not converge")
    print("CKA_PAGES_PROJECT_OK")


def ensure_domain() -> None:
    if not existing_project():
        raise RuntimeError("CKA project missing: refusing DNS mutation")
    # Inspect the exact host again before any change.
    dns_record()
    status, obj = request("GET", domain_path())
    if status == 404:
        status, obj = request("POST", project_path() + "/domains", {"name": HOST})
    if status not in (200, 201) or not isinstance(obj, dict) or obj.get("name") != HOST:
        raise RuntimeError("Could not associate dedicated CKA Pages domain")
    if obj.get("status") in ("blocked", "deactivated", "error"):
        raise RuntimeError("Pages domain has an error state")
    if dns_record() is None:
        status, _ = request("POST", dns_path(), {
            "type": "CNAME", "name": HOST, "content": TARGET, "proxied": True,
            "ttl": 1,
        })
        if status not in (200, 201):
            raise RuntimeError("Unable to create dedicated CKA DNS record")
    if dns_record() is None:
        raise RuntimeError("CKA DNS record did not converge")
    print("CKA_PAGES_DOMAIN_OK " + HOST)


def verify(sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Expected immutable source SHA")
    # Cloudflare's edge certificate/DNS may need additional time after initial setup.
    expires = time.monotonic() + 420
    context = ssl.create_default_context()
    while True:
        try:
            def get(path: str) -> bytes:
                req = urllib.request.Request("https://" + HOST + path, headers={
                    "Cache-Control": "no-cache", "User-Agent": "ShadowOps-CKA-Release/1",
                })
                with urllib.request.urlopen(req, timeout=12, context=context) as response:
                    if response.status != 200:
                        raise RuntimeError("Public HTTPS returned non-200")
                    return response.read(1024 * 1024)
            raw = get("/release.json")
            manifest = json.loads(raw)
            html = get("/").decode("utf-8", errors="replace")
            if (isinstance(manifest, dict) and manifest.get("application") == "cka-exam-simulator" and manifest.get("build") == sha
                    and manifest.get("mode") == "account-staging-preview"
                    and "CKA // LAB" in html):
                print("CKA_ACCOUNT_PAGES_LIVE_SHA_OK " + sha)
                return
        except (RuntimeError, ValueError, urllib.error.URLError, TimeoutError, OSError):
            pass
        if time.monotonic() >= expires:
            raise RuntimeError("CKA public HTTPS did not converge to admitted source SHA")
        time.sleep(12)


def disable_domain():
    # Validate ownership before deleting either binding; never delete the project.
    record = dns_record()
    exists = existing_project()
    if exists:
        status, domain = request("GET", domain_path())
        if status == 200:
            if not isinstance(domain, dict) or domain.get('name') != HOST:
                raise RuntimeError('Unexpected account Pages domain')
            result, _ = request('DELETE', domain_path())
            if result not in (200, 404): raise RuntimeError('Account domain removal failed')
        elif status != 404: raise RuntimeError('Cannot inspect account Pages domain')
    if record is not None:
        identifier = record.get('id')
        if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
            raise RuntimeError('Invalid owned DNS identity')
        result, _ = request('DELETE', dns_path()+'/'+identifier)
        if result not in (200, 404): raise RuntimeError('Account DNS removal failed')
    print('CKA_ACCOUNT_PAGES_DISABLED')


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: cka_account_pages.py preflight|project|domain|verify <SHA>")
    cmd = sys.argv[1]
    try:
        if cmd == "disable":
            disable_domain()
        elif cmd == "preflight":
            preflight()
        elif cmd == "project":
            ensure_project()
        elif cmd == "domain":
            ensure_domain()
        elif cmd == "verify" and len(sys.argv) == 3:
            verify(sys.argv[2])
        else:
            raise RuntimeError("Invalid command or arguments")
    except RuntimeError as exc:
        print("CKA_PAGES_ERROR " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
