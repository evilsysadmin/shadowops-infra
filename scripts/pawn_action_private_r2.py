#!/usr/bin/env python3
"""Read-only custody gate for a NEW non-public Pawn Action staging R2 bucket.

No shared Chess Studio bucket, public R2 URL, Cloudflare write, secret
provisioning, bucket creation, Pages deployment or release publication.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any

from cloudflare_control_plane import CloudflareReadClient, InventoryError

BUCKET = "pawn-action-staging-private"
BINDING = "PAWN_ACTION_PRIVATE_R2"
SHARED_PUBLIC_BUCKET = "chess-studio-assets"
ACCOUNT = re.compile(r"[a-f0-9]{32}\Z")


def inspect(client: Any) -> dict[str, str | bool]:
    """Confirm exact ownership and BOTH Cloudflare R2 public-access surfaces.

    An absent bucket is allowed only as a *pending* observation, never
    as evidence of privacy or authorization to publish.
    """
    account = getattr(client, "account", "")
    if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
        raise InventoryError("Exact Cloudflare account identity required")
    if BUCKET != "pawn-action-staging-private" or BUCKET == SHARED_PUBLIC_BUCKET:
        raise InventoryError("Private Pawn Action bucket identity is not pinned")

    base = f"/accounts/{account}/r2/buckets/{BUCKET}"
    status, bucket = client.get(base, allow_missing=True)
    if status == 404 and bucket is None:
        return {
            "bucket": "absent",
            "r2_dev": "unchecked",
            "custom_domains": "unchecked",
            "private": False,
        }
    if status != 200 or not isinstance(bucket, dict) or bucket.get("name") != BUCKET:
        raise InventoryError("R2 bucket missing, foreign, or returned an incomplete identity")

    managed_status, managed = client.get(base + "/domains/managed")
    if (managed_status != 200 or not isinstance(managed, dict)
            or managed.get("enabled") is not False):
        raise InventoryError("Pawn Action r2.dev public access is enabled or unverified")

    custom_status, custom = client.get(base + "/domains/custom")
    if (custom_status != 200 or not isinstance(custom, dict)
            or not isinstance(custom.get("domains"), list)):
        raise InventoryError("Pawn Action custom domains inventory missing or incomplete")
    # Even disabled custom-domain associations are refused: the bucket's
    # privacy must not depend on a domain that could be enabled later.
    if custom["domains"]:
        raise InventoryError("Private Pawn Action R2 bucket must have no custom domains")

    return {
        "bucket": "owned",
        "r2_dev": "disabled",
        "custom_domains": "none",
        "private": True,
    }


def self_test() -> None:
    assert BUCKET == "pawn-action-staging-private"
    assert BINDING == "PAWN_ACTION_PRIVATE_R2"
    assert BUCKET != SHARED_PUBLIC_BUCKET
    assert ACCOUNT.fullmatch("f" * 32)
    assert not ACCOUNT.fullmatch("football")
    print("PAWN_ACTION_PRIVATE_R2_CONTRACT_OK")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in (
            "self-test", "inventory", "require-private"):
        print("Usage: pawn_action_private_r2.py self-test|inventory|require-private",
              file=sys.stderr)
        return 2
    if sys.argv[1] == "self-test":
        self_test()
        return 0
    try:
        result = inspect(CloudflareReadClient(os.environ))
        if sys.argv[1] == "require-private" and not result["private"]:
            raise InventoryError("Private R2 bucket not provisioned; publication blocked")
    except InventoryError as exc:
        print("PAWN_ACTION_PRIVATE_R2_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("PAWN_ACTION_PRIVATE_R2_BLOCKED: " + type(exc).__name__,
              file=sys.stderr)
        return 1
    for key in ("bucket", "r2_dev", "custom_domains", "private"):
        print(f"PAWN_ACTION_PRIVATE_R2_{key.upper()} {str(result[key]).lower()}")
    print("PAWN_ACTION_PRIVATE_R2_READ_ONLY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
