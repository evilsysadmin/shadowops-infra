#!/usr/bin/env python3
"""Read-only Cloudflare Pages/DNS inventory for isolated Snooker staging.

No Cloudflare mutations, no source deployment, and no claim of Identity gating.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_PATTERN = re.compile(r"[a-fA-F0-9]{32}\Z")
PROJECT = "snooker-staging"
HOST = "staging.snooker.shadowops.dpdns.org"
ZONE = "shadowops.dpdns.org"
ALIAS_PATTERN = re.compile(r"snooker-staging(?:-[a-z0-9]+)?\.pages\.dev\Z")
BAD_STATUSES = {"blocked", "deactivated", "error"}


class InventoryError(ValueError):
    pass


class CloudflareClient:
    def __init__(self, env: Mapping[str, str]):
        account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        token = env.get("CLOUDFLARE_API_TOKEN", "").strip()
        if not ACCOUNT_PATTERN.fullmatch(account):
            raise InventoryError("Missing or invalid Cloudflare account ID")
        if not token:
            raise InventoryError("Missing Cloudflare inventory credential")
        self.account = account
        self._token = token

    def get(self, path: str):
        if not path.startswith("/") or ".." in path or "://" in path:
            raise InventoryError("Unsafe Cloudflare read path")
        req = urllib.request.Request(
            API + path,
            method="GET",
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                status, raw = response.status, response.read(2_000_001)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(2_000_001)
        except urllib.error.URLError:
            raise InventoryError("Cloudflare inventory unavailable") from None
        if len(raw) > 2_000_000:
            raise InventoryError("Cloudflare inventory response exceeds limit")
        if status == 404:
            return None
        if status != 200:
            raise InventoryError("Cloudflare GET failed (HTTP " + str(status) + ")")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise InventoryError("Invalid Cloudflare inventory JSON") from None
        if not isinstance(data, dict) or data.get("success") is not True:
            raise InventoryError("Cloudflare inventory request was rejected")
        return data.get("result")


def inspect(client) -> dict[str, str]:
    """Classify only resources under the exact Snooker identity; fail on foreign assets."""
    account = client.account
    query = urllib.parse.urlencode({"name": ZONE, "account.id": account})
    zones = client.get("/zones?" + query)
    if not isinstance(zones, list):
        raise InventoryError("Cannot resolve Cloudflare DNS zone")
    matches = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
        raise InventoryError("Missing or ambiguous managed DNS zone")
    zone = matches[0]["id"]

    project_path = "/accounts/" + account + "/pages/projects/" + PROJECT
    project = client.get(project_path)
    alias = None
    if project is not None:
        if not isinstance(project, dict) or project.get("name") != PROJECT:
            raise InventoryError("Foreign Pages project identity")
        if project.get("production_branch") != "main" or project.get("source"):
            raise InventoryError("Foreign Pages source integration or branch")
        alias = project.get("subdomain")
        if not isinstance(alias, str) or not ALIAS_PATTERN.fullmatch(alias):
            raise InventoryError("Unexpected Pages alias")
        domains = project.get("domains") or []
        if not isinstance(domains, list) or any(
            not isinstance(name, str) or name not in {HOST, alias}
            for name in domains
        ):
            raise InventoryError("Pages project has foreign custom domains")

    domain_path = project_path + "/domains/" + urllib.parse.quote(HOST, safe="")
    domain = client.get(domain_path) if project is not None else None
    if domain is not None:
        if not isinstance(domain, dict) or domain.get("name") != HOST:
            raise InventoryError("Foreign Pages custom domain")
        if domain.get("status") in BAD_STATUSES:
            raise InventoryError("Pages custom domain is unhealthy")
    if project is not None and HOST in (project.get("domains") or []) and domain is None:
        raise InventoryError("Inconsistent Pages domain inventory")

    dns_path = (
        "/zones/" + urllib.parse.quote(zone, safe="") + "/dns_records?"
        + urllib.parse.urlencode({"name": HOST, "per_page": 100})
    )
    records = client.get(dns_path)
    if not isinstance(records, list):
        raise InventoryError("Cannot inspect Snooker DNS")
    matching = [r for r in records if isinstance(r, dict) and r.get("name") == HOST]
    if len(matching) > 1:
        raise InventoryError("Duplicate DNS ownership")
    if matching:
        record = matching[0]
        if (
            alias is None
            or record.get("type") != "CNAME"
            or record.get("proxied") is not True
            or str(record.get("content", "")).rstrip(".") != alias
        ):
            raise InventoryError("Refusing foreign or unsafe Snooker DNS record")

    return {
        "project": "present" if project is not None else "absent",
        "domain": "present" if domain is not None else "absent",
        "dns": "present" if matching else "absent",
        # Inventory alone can never demonstrate authentication or authorization.
        "identity_gate": "not-verified",
        "deployment": "not-verified",
    }


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"plan", "inspect"}:
        print("Usage: snooker_pages_readiness.py plan|inspect", file=sys.stderr)
        return 2
    if sys.argv[1] == "plan":
        print("SNOOKER_STAGING_PLAN read-only=true host=" + HOST
              + " project=" + PROJECT + " identity_gate=not-verified")
        return 0
    try:
        result = inspect(CloudflareClient(os.environ))
    except InventoryError as exc:
        print("SNOOKER_STAGING_INVENTORY_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print("SNOOKER_STAGING_INVENTORY " + " ".join(
        key + "=" + value for key, value in result.items()
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
