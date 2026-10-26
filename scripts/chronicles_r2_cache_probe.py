#!/usr/bin/env python3
"""Read-only R2 domain and public browser-cache readiness probe for Chronicles.

Cloudflare's dashboard link cannot be used as a public asset URL. This probes
the real HTTPS custom domain and never mutates R2, DNS or cache rules.
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from cloudflare_control_plane import CloudflareReadClient, InventoryError

BUCKET = "chronicles"
ASSET_KEY = "sprites/ash-goblin.webp"
STAGING_ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"


def select_public_domain(result: Any) -> str | None:
    if not isinstance(result, dict) or not isinstance(result.get("domains"), list):
        raise InventoryError("R2 custom-domain inventory malformed")
    enabled = []
    for row in result["domains"]:
        if not isinstance(row, dict):
            raise InventoryError("R2 custom-domain item malformed")
        if row.get("enabled") is not True:
            continue
        name, status = row.get("domain"), row.get("status")
        if not isinstance(name, str) or not isinstance(status, dict):
            raise InventoryError("R2 domain metadata malformed")
        if status.get("ownership") != "active" or status.get("ssl") != "active":
            continue
        # Pin probes to our DNS zone; do not blindly HEAD arbitrary URLs.
        if not name.endswith(".shadowops.dpdns.org") or any(
            c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in name
        ):
            raise InventoryError("R2 custom domain lies outside the owned zone")
        enabled.append(name)
    if not enabled:
        return None
    if len(enabled) > 1:
        raise InventoryError("More than one active R2 custom domain: select explicitly")
    return enabled[0]


def inspect(client: Any, head: Callable[[str], tuple[int, dict[str, str]]]) -> dict[str, str]:
    _, domains = client.get(f"/accounts/{client.account}/r2/buckets/{BUCKET}/domains/custom")
    domain = select_public_domain(domains)
    if domain is None:
        return {"domain": "pending", "asset": "unverified"}
    url = f"https://{domain}/{urllib.parse.quote(ASSET_KEY, safe='/')}"
    status, headers = head(url)
    if status != 200:
        return {"domain": domain, "asset": f"http-{status}"}
    mime = headers.get("content-type", "").lower().split(";", 1)[0].strip()
    cors = headers.get("access-control-allow-origin", "")
    cache_control = headers.get("cache-control", "").lower()
    # A mutable key must never get one-year immutable caching.
    mutable_safe = "immutable" not in cache_control and "max-age=31536000" not in cache_control
    return {
        "domain": domain,
        "asset": "ok" if mime == "image/webp" else "wrong-content-type",
        "cors": "ok" if cors in ("*", STAGING_ORIGIN) else "missing-or-denied",
        "cache": "mutable-safe" if mutable_safe else "unsafe-immutable-mutable-key",
        "cache_header": cache_control[:128] or "absent",
    }


def head_public(url: str) -> tuple[int, dict[str, str]]:
    request = urllib.request.Request(
        url, method="HEAD",
        headers={"Origin": STAGING_ORIGIN, "User-Agent": "shadowops-r2-cache-probe/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except (urllib.error.URLError, TimeoutError):
        raise InventoryError("public R2 HTTPS HEAD unavailable") from None


def main() -> int:
    try:
        result = inspect(CloudflareReadClient(os.environ), head_public)
    except InventoryError as exc:
        print("CHRONICLES_R2_CACHE_PROBE_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    for key, value in sorted(result.items()):
        print("CHRONICLES_R2_CACHE_PROBE " + key + " " + value)
    return 0 if (
        result.get("domain") != "pending" and result.get("asset") == "ok"
        and result.get("cors") == "ok" and result.get("cache") == "mutable-safe"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
