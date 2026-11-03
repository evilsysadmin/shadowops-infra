#!/usr/bin/env python3
"""Read-only admission for Pawn Action's independent Cloudflare Pages staging DNS.

The release publisher is intentionally NOT implemented here: Infra must
separately admit an exact green Pawn Action main artifact and enforce its
runtime/identity policy before any Pages or R2 mutation.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.parse

from cloudflare_control_plane import CloudflareReadClient, InventoryError

ZONE = "shadowops.dpdns.org"
HOST = "staging.pawnaction.shadowops.dpdns.org"
PROJECT = "pawn-action-staging"
PAGES_TARGET = re.compile(r"^pawn-action-staging(?:-[a-z0-9]+)?\.pages\.dev$")
DENIED_DOMAIN_STATES = {"blocked", "deactivated", "error"}


def pages_target(project: dict) -> str:
    subdomain = project.get("subdomain")
    if not isinstance(subdomain, str) or not PAGES_TARGET.fullmatch(subdomain):
        raise InventoryError("Pawn Action Pages project has an unexpected assigned hostname")
    return subdomain


def inspect(client: CloudflareReadClient) -> dict[str, str]:
    if HOST != "staging.pawnaction.shadowops.dpdns.org" or not HOST.endswith("." + ZONE):
        raise InventoryError("Unexpected Pawn Action staging host or Cloudflare zone")

    query = urllib.parse.urlencode({"name": ZONE, "account.id": client.account})
    status, zones = client.get("/zones?" + query)
    if status != 200 or not isinstance(zones, list):
        raise InventoryError("Pawn Action zone lookup is incomplete")
    matches = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE and z.get("id")]
    if len(matches) != 1:
        raise InventoryError("Pawn Action zone must have exactly one known owner")
    zone_id = str(matches[0]["id"])

    project_path = f"/accounts/{client.account}/pages/projects/{PROJECT}"
    status, project = client.get(project_path, allow_missing=True)
    if status not in (200, 404):
        raise InventoryError("Pawn Action Pages project read failed")
    target = ""
    domain_status = "absent"
    if status == 200:
        if not isinstance(project, dict) or project.get("name") != PROJECT:
            raise InventoryError("Foreign Pages project under Pawn Action staging name")
        if project.get("production_branch") != "main" or project.get("source"):
            raise InventoryError("Pawn Action Pages project has an unexpected source or branch")
        target = pages_target(project)
        domains = project.get("domains")
        if not isinstance(domains, list) or any(
            not isinstance(d, str) or d not in (target, HOST) for d in domains
        ):
            raise InventoryError("Pawn Action Pages project contains foreign custom domains")
        domain_path = project_path + "/domains/" + urllib.parse.quote(HOST, safe="")
        domain_http, domain = client.get(domain_path, allow_missing=True)
        if domain_http == 200:
            if (not isinstance(domain, dict) or domain.get("name") != HOST
                    or domain.get("status") in DENIED_DOMAIN_STATES):
                raise InventoryError("Pawn Action Pages custom domain is foreign or unhealthy")
            domain_status = str(domain.get("status") or "pending")
        elif domain_http != 404:
            raise InventoryError("Pawn Action Pages domain lookup failed")

    dns_query = urllib.parse.urlencode({"name": HOST, "per_page": "100"})
    dns_http, rows = client.get(f"/zones/{zone_id}/dns_records?" + dns_query)
    if dns_http != 200 or not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise InventoryError("Pawn Action DNS response is incomplete or malformed")
    exact = [r for r in rows if r.get("name") == HOST]
    if len(exact) > 1:
        raise InventoryError("Ambiguous Pawn Action staging DNS ownership")
    if exact:
        row = exact[0]
        if not target or domain_status == "absent":
            raise InventoryError("Pawn Action DNS exists without its verified Pages project/domain")
        if (row.get("type") != "CNAME" or row.get("proxied") is not True
                or str(row.get("content") or "").rstrip(".") != target):
            raise InventoryError("Foreign Pawn Action staging DNS record; refusing adoption")

    return {
        "host": HOST,
        "pages": "owned" if target else "absent",
        "dns": "owned" if exact else "absent",
        "custom_domain": domain_status,
    }


def self_test() -> None:
    assert ZONE == "shadowops.dpdns.org"
    assert HOST == "staging.pawnaction.shadowops.dpdns.org"
    assert PROJECT == "pawn-action-staging"
    assert PAGES_TARGET.fullmatch("pawn-action-staging.pages.dev")
    assert PAGES_TARGET.fullmatch("pawn-action-staging-x1.pages.dev")
    assert not PAGES_TARGET.fullmatch("football-staging.pages.dev")
    assert not PAGES_TARGET.fullmatch("pawn-action-staging.evil.pages.dev")
    print("PAWN_ACTION_STAGING_DOMAIN_CONTRACT_OK")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("self-test", "inventory"):
        print("Usage: pawn_action_pages.py self-test|inventory", file=sys.stderr)
        return 2
    if sys.argv[1] == "self-test":
        self_test()
        return 0
    try:
        result = inspect(CloudflareReadClient(os.environ))
    except InventoryError as exc:
        print("PAWN_ACTION_STAGING_PREFLIGHT_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("PAWN_ACTION_STAGING_PREFLIGHT_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 1
    for key in ("host", "pages", "dns", "custom_domain"):
        print(f"PAWN_ACTION_STAGING_{key.upper()} {result[key]}")
    print("PAWN_ACTION_STAGING_READ_ONLY_PREFLIGHT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
