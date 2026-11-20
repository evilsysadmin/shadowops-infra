#!/usr/bin/env python3
"""Independently audit the isolated Bridge Squad Pages deployment without writes.

No production Identity assumption, no DNS mutation, no Pages upload. Intended
for scheduled/dispatch CI using only the protected Cloudflare inventory token.
"""
from __future__ import annotations

import os
import sys

import bridgesquad_alias_bootstrap as bootstrap
import bridgesquad_dns_quarantine as quarantine
import bridgesquad_pages_readiness as readiness
import bridgesquad_source_admission as source


class WatchdogBlocked(ValueError):
    pass


def audit(client, *, probe=bootstrap.guest_status) -> dict:
    path = "/accounts/" + client.account + "/pages/projects/" + readiness.PROJECT
    project = client.get(path)
    if not isinstance(project, dict):
        raise WatchdogBlocked("Bridge Squad Pages project unavailable")
    canonical = project.get("canonical_deployment")
    trigger = canonical.get("deployment_trigger") if isinstance(canonical, dict) else None
    metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    sha = metadata.get("commit_hash") if isinstance(metadata, dict) else None
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise WatchdogBlocked("Cannot establish immutable deployed game source")
    inventory = readiness.inspect(client)
    if inventory["domain"] == "present" and inventory["dns"] == "present":
        result = quarantine.audit(client, guest=probe, web=quarantine.https_probe, allow_bound=True)
    else:
        result = bootstrap.postflight(client, sha, status=probe)
    if int(result["aliases"]) < 2:
        raise WatchdogBlocked("Pages canonical immutable alias not discoverable")
    return result


def main() -> int:
    if sys.argv[1:] != ["audit"]:
        print("Usage: bridgesquad_alias_watchdog.py audit", file=sys.stderr)
        return 2
    try:
        result = audit(readiness.CloudflareClient(os.environ))
    except (OSError, ValueError, readiness.InventoryError) as exc:
        print("BRIDGESQUAD_ALIAS_WATCHDOG_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    print("BRIDGESQUAD_ALIAS_WATCHDOG_OK " + " ".join(k + "=" + str(v) for k, v in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
