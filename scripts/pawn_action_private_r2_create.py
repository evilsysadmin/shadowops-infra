#!/usr/bin/env python3
"""Manual, create-once Pawn Action private R2 bucket provisioner.

Only one possible Cloudflare write: POST the exact new bucket name.
Never adopt a public/foreign bucket, modify domains, upload objects,
change Pages/DNS, or touch the shared Chess Studio asset bucket.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Mapping

from cloudflare_control_plane import API, CloudflareReadClient, InventoryError
from pawn_action_private_r2 import BUCKET, ACCOUNT, inspect

WRITE_TOKEN = "PAWN_ACTION_R2_PROVISION_TOKEN"


class ProvisionError(Exception):
    pass


class BucketCreator:
    """Separate capability: only permitted to CREATE the dedicated bucket."""
    def __init__(self, env: Mapping[str, str]):
        self.account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        self.token = env.get(WRITE_TOKEN, "").strip()
        read_token = env.get("CLOUDFLARE_API_TOKEN", "").strip()
        if not ACCOUNT.fullmatch(self.account):
            raise ProvisionError("Exact Cloudflare account identity required")
        if not self.token or not read_token or self.token == read_token:
            raise ProvisionError("Independent write and read-only R2 tokens required")

    def create_bucket(self) -> dict:
        data = json.dumps({"name": BUCKET}, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            f"{API}/accounts/{self.account}/r2/buckets", data=data,
            method="POST", headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise ProvisionError("R2 create response status unverified")
                body = response.read(32769)
        except urllib.error.HTTPError as exc:
            raise ProvisionError("R2 create rejected (HTTP " + str(exc.code) + ")") from None
        except ProvisionError:
            raise
        except Exception:
            # A timeout is an UNKNOWN outcome: operator must re-inventory
            # rather than automatically retrying a potentially successful POST.
            raise ProvisionError("R2 creation outcome unknown; re-inventory before retry") from None
        if len(body) > 32768:
            raise ProvisionError("R2 create response exceeds safe limit")
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError):
            raise ProvisionError("R2 create response is invalid JSON") from None
        if (not isinstance(result, dict) or result.get("success") is not True
                or not isinstance(result.get("result"), dict)
                or result["result"].get("name") != BUCKET):
            raise ProvisionError("R2 create response did not confirm exact bucket")
        return result["result"]


def create_once(reader, creator, confirm: str) -> dict[str, str]:
    """One POST at most, then a mandatory fresh privacy check; no rollback delete."""
    if confirm != BUCKET:
        raise ProvisionError("Explicit exact private bucket confirmation required")
    if (not ACCOUNT.fullmatch(getattr(reader, "account", ""))
            or getattr(creator, "account", None) != reader.account):
        raise ProvisionError("Cloudflare reader/writer accounts must match exactly")

    before = inspect(reader)
    if before["private"] is True:
        # Idempotent without writes, but no guarantee that this was created
        # by this script. An operator still reviews custody separately.
        return {"bucket": BUCKET, "state": "already_private", "private": "true"}
    if before["bucket"] != "absent":
        raise ProvisionError("Unexpected existing R2 bucket state; create refused")

    # No retry on conflict, timeout, malformed response or failed post-check.
    creator.create_bucket()
    after = inspect(reader)
    if after["bucket"] != "owned" or after["private"] is not True:
        raise ProvisionError(
            "Bucket creation unverified or public; leave empty and investigate manually"
        )
    return {"bucket": BUCKET, "state": "created_private", "private": "true"}


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = argparse.ArgumentParser()
    args.add_argument("action", choices=("plan", "create"))
    args.add_argument("--confirm-bucket", default="")
    parsed = args.parse_args(argv)
    env = os.environ if env is None else env
    if parsed.action == "plan":
        print("PAWN_ACTION_R2_CREATE_PLAN " + json.dumps({
            "bucket": BUCKET, "writes": 0, "requiresExplicitConfirmation": True,
            "privateBucketOnly": True,
        }, sort_keys=True))
        return 0
    try:
        if parsed.confirm_bucket != BUCKET:
            raise ProvisionError("Exact --confirm-bucket value required")
        # Validate separate read and write credentials BEFORE Cloudflare I/O.
        writer = BucketCreator(env)
        reader = CloudflareReadClient(env)
        outcome = create_once(reader, writer, parsed.confirm_bucket)
    except (ProvisionError, InventoryError) as exc:
        print("PAWN_ACTION_R2_CREATE_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("PAWN_ACTION_R2_CREATE_BLOCKED: unexpected error", file=sys.stderr)
        return 1
    print("PAWN_ACTION_R2_CREATE_VERIFIED " + json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
