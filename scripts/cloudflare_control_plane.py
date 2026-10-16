#!/usr/bin/env python3
"""Read-only Cloudflare inventory for the EXISTING Matthias DNS/Pages/Tunnel.

ShadowOps must observe each resource before taking over the owner role.
No token transfer, DNS mutation, Pages deployment or Tunnel configuration.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
TUNNEL = "chess-studio-staging"
HOSTS = (
    "chess-studio.shadowops.dpdns.org",
    "staging.chess-studio.shadowops.dpdns.org",
    "api-staging.chess-studio.shadowops.dpdns.org",
    "api.chess-studio.shadowops.dpdns.org",
    "ssh-chess-studio-staging.shadowops.dpdns.org",
    "chronicles.shadowops.dpdns.org",
    "staging.chronicles.shadowops.dpdns.org",
)
PROJECTS = {
    "chess-studio-staging": "staging.chess-studio.shadowops.dpdns.org",
    "chronicles-staging": "staging.chronicles.shadowops.dpdns.org",
}


class InventoryError(Exception):
    pass


class CloudflareReadClient:
    def __init__(self, env: Mapping[str, str]):
        self.token = env.get("CLOUDFLARE_API_TOKEN", "").strip()
        self.account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        if not self.token or not self.account:
            raise InventoryError("ShadowOps Cloudflare read credentials are not configured")
        if not self.account.replace("-", "").isalnum():
            raise InventoryError("Cloudflare account identity malformed")

    def get(self, path: str, *, allow_missing: bool = False) -> tuple[int, Any]:
        if not path.startswith("/") or "://" in path or ".." in path:
            raise InventoryError("Unsafe Cloudflare path")
        req = urllib.request.Request(
            API + path, method="GET",
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                status, data = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, data = exc.code, exc.read()
        if status == 404 and allow_missing:
            return 404, None
        if status != 200:
            raise InventoryError(f"Cloudflare read-only request failed (HTTP {status})")
        try:
            body = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise InventoryError("Cloudflare did not return JSON") from None
        if not isinstance(body, dict) or body.get("success") is not True:
            raise InventoryError("Cloudflare API did not confirm success")
        return 200, body.get("result")


def _one(rows: Any, description: str) -> Any:
    if not isinstance(rows, list):
        raise InventoryError(f"Cloudflare {description} response malformed")
    if len(rows) != 1:
        raise InventoryError(f"Expected exactly one {description}, found {len(rows)}")
    return rows[0]


def inspect(client: Any) -> dict[str, str]:
    zone_query = urllib.parse.urlencode({"name": ZONE, "account.id": client.account, "per_page": "50"})
    _, zones = client.get("/zones?" + zone_query)
    zone = _one([r for r in zones if isinstance(r, dict) and r.get("name") == ZONE], "zone")
    zid = str(zone.get("id") or "")
    if not zid:
        raise InventoryError("Cloudflare zone has no ID")

    results: dict[str, str] = {}
    for hostname in HOSTS:
        query = urllib.parse.urlencode({"name": hostname, "per_page": "100"})
        _, rows = client.get(f"/zones/{zid}/dns_records?{query}")
        if not isinstance(rows, list):
            raise InventoryError("Cloudflare DNS listing malformed")
        exact = [r for r in rows if isinstance(r, dict) and r.get("name") == hostname]
        if len(exact) > 1:
            raise InventoryError("Ambiguous DNS ownership: " + hostname)
        if exact:
            row = exact[0]
            record_type = str(row.get("type", ""))
            if record_type not in {"A", "AAAA", "CNAME"}:
                raise InventoryError("Unexpected DNS record type for " + hostname)
            results["dns:" + hostname] = record_type + (":proxied" if row.get("proxied") is True else ":unproxied")
        else:
            # Chronicles was deliberately not assumed live before adoption.
            if hostname.startswith(("staging.chess-studio.", "api-staging.chess-studio.")):
                raise InventoryError("Existing Chess Studio staging DNS missing: " + hostname)
            results["dns:" + hostname] = "absent"

    tunnel_query = urllib.parse.urlencode({"name": TUNNEL, "is_deleted": "false", "per_page": "100"})
    _, tunnels = client.get(f"/accounts/{client.account}/cfd_tunnel?{tunnel_query}")
    _one([r for r in tunnels if isinstance(r, dict) and r.get("name") == TUNNEL], "existing Chess Studio tunnel")
    results["tunnel:" + TUNNEL] = "present"

    for project, hostname in PROJECTS.items():
        prefix = f"/accounts/{client.account}/pages/projects/{project}"
        status, data = client.get(prefix, allow_missing=project == "chronicles-staging")
        if status == 404:
            results["pages:" + project] = "pending"
            continue
        if not isinstance(data, dict) or data.get("name") != project:
            raise InventoryError("Unexpected Pages project identity: " + project)
        if data.get("production_branch") != "main":
            raise InventoryError("Unexpected Pages production branch: " + project)
        _, domain = client.get(prefix + "/domains/" + urllib.parse.quote(hostname, safe=""),
                               allow_missing=project == "chronicles-staging")
        if not isinstance(domain, dict) or domain.get("name") != hostname:
            if project == "chronicles-staging" and domain is None:
                results["pages:" + project] = "domain-pending"
                continue
            raise InventoryError("Existing Pages custom-domain identity mismatch: " + project)
        state = str(domain.get("status") or "unknown")
        if state in {"blocked", "deactivated", "error"}:
            raise InventoryError("Pages custom domain is not healthy: " + project)
        results["pages:" + project] = state

    return results


def self_test() -> None:
    assert TUNNEL == "chess-studio-staging"
    assert PROJECTS["chronicles-staging"] == "staging.chronicles.shadowops.dpdns.org"
    assert len(HOSTS) == len(set(HOSTS))
    assert len(PROJECTS) == 2
    print("SHADOWOPS_CLOUDFLARE_INVENTORY_SELF_TEST_OK")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("inventory", "self-test"))
    args = parser.parse_args()
    if args.operation == "self-test":
        self_test()
        return 0
    try:
        client = CloudflareReadClient(os.environ)
        data = inspect(client)
    except InventoryError as exc:
        print("SHADOWOPS_CLOUDFLARE_INVENTORY_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("SHADOWOPS_CLOUDFLARE_INVENTORY_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 1
    for name in sorted(data):
        print("SHADOWOPS_CLOUDFLARE_RESOURCE " + name + " " + data[name])
    print("SHADOWOPS_CLOUDFLARE_INVENTORY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
