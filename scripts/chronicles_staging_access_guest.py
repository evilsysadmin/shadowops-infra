#!/usr/bin/env python3
"""Read-only guest postflight for Chronicles staging *immutable* Pages URLs.

The main Pages alias and canonical custom domain are deliberately OUT of scope.
A passing sample does not prove complete historical inventory, cryptographic
Access enforcement, authorized login, or ShadowOps ID isolation.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys

from game_identity_pages_history import (
    GuestProbe, InventoryError, MAX_HOSTS_PER_PROJECT,
    PATHS, fetch_pages_guest, list_hosts,
)
from game_identity_exposure import GAMES
from staradvs_pages import CloudflareClient

PROJECT = "chronicles-staging"
ROOT = PROJECT + ".pages.dev"
MAX_WORKERS = 8


class PostflightError(Exception):
    pass


def probe(client, request_status=fetch_pages_guest):
    owned = [g for g in GAMES if g.pages_project == PROJECT
             and g.environment == "staging" and g.slug == "chronicles-of-matthias"]
    if len(owned) != 1:
        raise PostflightError("Expected game ownership registry not exact")
    try:
        hosts, complete = list_hosts(client, owned[0])
    except Exception:
        # Provider errors and host metadata may contain private account
        # details. Never log the exception or any opaque alias.
        raise PostflightError("Provider history not readable") from None
    if not isinstance(hosts, list) or ROOT not in hosts or len(set(hosts)) != len(hosts):
        raise PostflightError("Unexpected Pages host census")
    previews = [host for host in hosts if host != ROOT]
    if (not previews or len(previews) > MAX_HOSTS_PER_PROJECT or
            any(not isinstance(host, str) or
                re.fullmatch(r"[a-z0-9-]{1,63}\." + re.escape(ROOT), host) is None
                for host in previews)):
        raise PostflightError("Sample missing, oversized, or outside project")
    # The Cloudflare client does not return reliable pagination metadata:
    # even a clean sample MUST be labelled incomplete.
    if complete is True:
        raise PostflightError("Unexpected history-completeness contract")
    def fetch(target):
        host, path = target
        try:
            result = request_status("https://" + host + path, "GET")
            if not isinstance(result, GuestProbe):
                return 0, False
            if type(result.status) is not int or type(result.access_login) is not bool:
                return 0, False
            return result.status, result.access_login
        except Exception:
            return 0, False

    tasks = [(host, path) for host in previews for path in PATHS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(fetch, tasks))
    exposed = sum(code in (200, 206) for code, _ in results)
    challenged = sum(
        (code in (302, 303, 307) and is_access)
        for code, is_access in results
    )
    denied = sum(code in (401, 403) for code, _ in results)
    unverified = len(results) - exposed - challenged - denied
    if exposed:
        state = "ANONYMOUS_PREVIEW_CONTENT_OBSERVED"
    elif unverified:
        state = "PREVIEW_GUEST_SAMPLE_UNVERIFIED"
    else:
        state = "GUEST_DENIAL_OBSERVED_SAMPLE_ONLY"
    return {
        "state": state,
        "project": PROJECT,
        "preview_hosts_sampled": len(previews),
        "guest_requests": len(results),
        "anonymous_200_206_requests": exposed,
        "access_login_challenge_requests": challenged,
        "denied_401_403_requests": denied,
        "unverified_requests": unverified,
        "historic_inventory_complete": False,
        "base_pages_alias_checked": False,
        "canonical_custom_domain_checked": False,
        "shadowops_id_authenticated_e2e": False,
        "fully_protected": False,
    }


def main(argv):
    if argv != ["verify-sample"]:
        print("Usage: chronicles_staging_access_guest.py verify-sample", file=sys.stderr)
        return 64
    try:
        result = probe(CloudflareClient(os.environ))
    except Exception as exc:
        print("CHRONICLES_STAGING_ACCESS_GUEST_UNAVAILABLE kind=" +
              type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    if result["state"] == "ANONYMOUS_PREVIEW_CONTENT_OBSERVED":
        return 1
    if result["state"] == "GUEST_DENIAL_OBSERVED_SAMPLE_ONLY":
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
