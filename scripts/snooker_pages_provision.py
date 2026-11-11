#!/usr/bin/env python3
"""Create only dedicated Snooker Pages project and fail-closed policy, never DNS/deploy."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

import snooker_pages_readiness as readiness

class ProvisionError(ValueError):
    pass


def safe_provider_code(raw):
    """Return only one bounded numeric Cloudflare API code; never the response text."""
    if not isinstance(raw, bytes) or len(raw) > 8192:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("errors"), list):
        return None
    codes = [row.get("code") for row in value["errors"]
             if isinstance(row, dict) and type(row.get("code")) is int
             and 0 < row["code"] <= 999999999]
    return str(codes[0]) if len(codes) == 1 else None


class Client(readiness.CloudflareClient):
    def write(self, method, path, value):
        if method not in {"POST", "PATCH"} or not path.startswith("/") or ".." in path:
            raise ProvisionError("Unsafe Cloudflare write")
        req = urllib.request.Request(
            readiness.API + path,
            method=method,
            data=json.dumps(value).encode("utf-8"),
            headers={"Authorization": "Bearer " + self._token,
                     "Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                status, raw = response.status, response.read(2_000_001)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(2_000_001)
        except urllib.error.URLError:
            raise ProvisionError("Cloudflare unavailable") from None
        if status not in (200, 201) or len(raw) > 2_000_000:
            code = safe_provider_code(raw)
            # Only the numerical HTTP status and provider code are admissible
            # outside this module. Never propagate provider message/pointer.
            raise ProvisionError("Cloudflare write rejected (HTTP " + str(status) + ")"
                                 + (" API " + code if code is not None else ""))
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ProvisionError("Cloudflare returned invalid JSON") from None
        if not isinstance(result, dict) or result.get("success") is not True:
            raise ProvisionError("Cloudflare rejected Pages mutation")
        return result.get("result")

def ensure(client):
    # Verify ownership of the *entire* dedicated resource set before writing.
    inventory = readiness.inspect(client)
    path = "/accounts/" + client.account + "/pages/projects/" + readiness.PROJECT
    if inventory["project"] == "absent":
        if inventory["domain"] != "absent" or inventory["dns"] != "absent":
            raise ProvisionError("Orphaned Pages domain/DNS cannot be adopted")
        created = client.write("POST", "/accounts/" + client.account + "/pages/projects", {
            "name": readiness.PROJECT, "production_branch": "main",
        })
        if not isinstance(created, dict) or created.get("name") != readiness.PROJECT:
            raise ProvisionError("Pages project creation returned foreign identity")
    inventory = readiness.inspect(client)
    if inventory["project"] != "present":
        raise ProvisionError("Dedicated project not visible after creation")
    project = client.get(path)
    configs = project.get("deployment_configs") or {}
    if not isinstance(configs, dict):
        raise ProvisionError("Unexpected Pages environment configuration")
    settings = {}
    for mode in ("production", "preview"):
        original = configs.get(mode) or {}
        if not isinstance(original, dict):
            raise ProvisionError("Unexpected Pages environment mode")
        flags = original.get("compatibility_flags") or []
        if not isinstance(flags, list) or any(not isinstance(f, str) for f in flags):
            raise ProvisionError("Invalid Pages compatibility flags")
        if "global_fetch_private_origin" in flags:
            raise ProvisionError("Identity HTTPS origin must remain public-routed")
        settings[mode] = {
            "fail_open": False,
            "compatibility_flags": sorted(set(flags) | {"global_fetch_strictly_public"}),
        }
    # The same fail-closed flags apply to every preview branch deployment.
    client.write("PATCH", path, {"deployment_configs": settings})
    updated = client.get(path)
    if not isinstance(updated, dict):
        raise ProvisionError("Cannot verify post-write project")
    current = updated.get("deployment_configs") or {}
    for mode in ("production", "preview"):
        cfg = current.get(mode) or {}
        if cfg.get("fail_open") is not False or (
            "global_fetch_strictly_public" not in (cfg.get("compatibility_flags") or [])
        ):
            raise ProvisionError("Pages identity policy did not converge")
    # Reclassify ownership after patch; NEVER assign domain/DNS or publish assets.
    after = readiness.inspect(client)
    if after["project"] != "present":
        raise ProvisionError("Pages project ownership changed")
    return {
        "project": readiness.PROJECT, "production_fail_open": "false",
        "preview_fail_open": "false", "domain": after["domain"], "dns": after["dns"],
        "deployed": "false",
    }

def main():
    if sys.argv[1:] != ["project"]:
        print("Usage: snooker_pages_provision.py project", file=sys.stderr)
        return 2
    try:
        result = ensure(Client(os.environ))
    except (readiness.InventoryError, ProvisionError) as exc:
        print("SNOOKER_PAGES_PROVISION_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    print("SNOOKER_PAGES_PRIVATE_PROJECT " + " ".join(f"{k}={v}" for k, v in result.items()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
