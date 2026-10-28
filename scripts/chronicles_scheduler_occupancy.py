#!/usr/bin/env python3
"""Read-only Cloudflare guard: never overwrite an existing scheduler Worker."""
from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request

SCRIPT_NAME = "shadowops-chronicles-production-scheduler"
ACCOUNT_RE = re.compile(r"[0-9a-f]{32}\Z")
API_ROOT = "https://api.cloudflare.com/client/v4/accounts"


class OccupancyError(RuntimeError):
    pass


def assert_worker_absent(account_id: str, token: str, *, opener=urllib.request.urlopen) -> None:
    """Allow first installation only after an authenticated exact-name 404."""
    if not isinstance(account_id, str) or not ACCOUNT_RE.fullmatch(account_id):
        raise OccupancyError("invalid Cloudflare account identifier")
    if not isinstance(token, str) or not token.strip():
        raise OccupancyError("missing Cloudflare API token")
    url = f"{API_ROOT}/{account_id}/workers/scripts/{SCRIPT_NAME}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "ShadowOpsChroniclesSchedulerPreflight/1",
        },
    )
    try:
        with opener(req, timeout=15) as response:
            # Any successful lookup means the script name is already claimed.
            # No need to inspect or log script contents.
            if response.geturl() != url:
                raise OccupancyError("unexpected Cloudflare response origin")
            raise OccupancyError("scheduler Worker already exists; deployment refused")
    except urllib.error.HTTPError as exc:
        # A 404 means the exact-name Worker is not present. Other statuses
        # (including auth, rate-limit or provider outage) fail closed.
        if exc.geturl() != url or exc.code != 404:
            raise OccupancyError("Cloudflare Worker occupancy cannot be verified") from None


def main() -> int:
    try:
        assert_worker_absent(
            os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
            os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        )
    except (OccupancyError, urllib.error.URLError, TimeoutError, OSError) as exc:
        # Only emit our own safe reason, never a token or provider response body.
        label = str(exc) if isinstance(exc, OccupancyError) else "Cloudflare lookup unavailable"
        print("CHRONICLES_SCHEDULER_OCCUPANCY_BLOCKED " + label, file=sys.stderr)
        return 1
    print("CHRONICLES_SCHEDULER_NAME_AVAILABLE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
