#!/usr/bin/env python3
"""Dedicated FOOTBALL static-preview Pages owner; no Kubernetes, OCI or tunnel operations."""
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
HOST = "staging.football.shadowops.dpdns.org"
PROJECT = "football-staging"
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


def project_target(project: dict) -> str:
    target = project.get('subdomain', '')
    if not isinstance(target, str) or not re.fullmatch(r'football-staging(?:-[a-z0-9]+)?\.pages\.dev', target):
        raise RuntimeError('Unexpected Football Pages assigned subdomain')
    return target


def dns_target() -> str:
    status, project = request('GET', project_path())
    if status == 404:
        return TARGET
    if not existing_project() or not isinstance(project, dict):
        raise RuntimeError('Cannot identify Football DNS target')
    return project_target(project)


def dns_record() -> dict | None:
    status, rows = request("GET", dns_path() + "?" + urllib.parse.urlencode({"name": HOST}))
    if status != 200 or not isinstance(rows, list):
        raise RuntimeError("Cannot inspect FOOTBALL DNS")
    matching = [row for row in rows if isinstance(row, dict) and row.get("name") == HOST]
    if len(matching) > 1:
        raise RuntimeError("Ambiguous FOOTBALL DNS: multiple records")
    if matching:
        record = matching[0]
        if (record.get("type") != "CNAME" or record.get("proxied") is not True
                or str(record.get("content", "")).rstrip(".") != dns_target()):
            raise RuntimeError("Refusing to overwrite an existing foreign FOOTBALL DNS record")
        return record
    return None


def existing_project() -> bool:
    status, project = request("GET", project_path())
    if status == 404:
        return False
    if status != 200 or not isinstance(project, dict):
        raise RuntimeError("Cannot inspect FOOTBALL Pages project")
    if project.get("name") != PROJECT or project.get("production_branch") != "main":
        raise RuntimeError("Unexpected FOOTBALL Pages project identity or branch")
    if project.get('source') or set(project.get('domains') or []) - {HOST,project_target(project)}:
        raise RuntimeError('Refusing a foreign Football project integration/domain')
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
            raise RuntimeError("Unexpected existing FOOTBALL Pages domain")
        if status not in (200, 404):
            raise RuntimeError("Unable to inspect FOOTBALL Pages domain")
    print("FOOTBALL_PAGES_OWNERSHIP_PREFLIGHT_OK " + HOST)


def ensure_project() -> None:
    if not existing_project():
        status, created = request("POST", "/accounts/" + required("CLOUDFLARE_ACCOUNT_ID") + "/pages/projects", {
            "name": PROJECT, "production_branch": "main",
        })
        if status not in (200, 201) or not isinstance(created, dict) or created.get("name") != PROJECT:
            raise RuntimeError("Failed to create dedicated FOOTBALL Pages project")
    if not existing_project():
        raise RuntimeError("Pages project did not converge")
    print("FOOTBALL_PAGES_PROJECT_OK")


def ensure_domain() -> None:
    if not existing_project():
        raise RuntimeError("FOOTBALL project missing: refusing DNS mutation")
    # Inspect the exact host again before any change.
    dns_record()
    status, obj = request("GET", domain_path())
    if status == 404:
        status, obj = request("POST", project_path() + "/domains", {"name": HOST})
    if status not in (200, 201) or not isinstance(obj, dict) or obj.get("name") != HOST:
        raise RuntimeError("Could not associate dedicated FOOTBALL Pages domain")
    if obj.get("status") in ("blocked", "deactivated", "error"):
        raise RuntimeError("Pages domain has an error state")
    if dns_record() is None:
        status, _ = request("POST", dns_path(), {
            "type": "CNAME", "name": HOST, "content": dns_target(), "proxied": True,
            "ttl": 1,
        })
        if status not in (200, 201):
            raise RuntimeError("Unable to create dedicated FOOTBALL DNS record")
    if dns_record() is None:
        raise RuntimeError("FOOTBALL DNS record did not converge")
    print("FOOTBALL_PAGES_DOMAIN_OK " + HOST)



def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: football_pages.py preflight|project|domain|verify <SHA>")
    cmd = sys.argv[1]
    try:
        if cmd == "preflight":
            preflight()
        elif cmd == "project":
            ensure_project()
        elif cmd == "domain":
            ensure_domain()
        elif cmd == "verify" and len(sys.argv) == 3:
            from football_delivery import verify_public
            verify_public(sys.argv[2])
        else:
            raise RuntimeError("Invalid command or arguments")
    except RuntimeError as exc:
        print("FOOTBALL_PAGES_ERROR " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
