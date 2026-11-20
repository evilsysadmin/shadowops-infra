#!/usr/bin/env python3
"""Read-only production release admission for the existing Bridge Squad Pages host.

This module NEVER deploys, creates DNS, binds secrets, opens pages, or mints a
user. The independently protected GitHub Actions workflow may promote only a
verified current game main release after these checks have passed.
"""
from __future__ import annotations

import os
import sys
import uuid

import bridgesquad_dns_quarantine as quarantine
import bridgesquad_pages_readiness as readiness
import bridgesquad_prod_identity_probe as identity
import bridgesquad_production_proof_bind as proof
import bridgesquad_source_admission as source

PROJECT_PATH = "/accounts/{account}/pages/projects/" + readiness.PROJECT


class Refused(ValueError):
    pass


def _sha(value: str) -> str:
    if not isinstance(value, str) or not source.SHA.fullmatch(value):
        raise Refused("exact lowercase game source SHA required")
    return value


def _deployment_id(value) -> str:
    """Canonical Cloudflare deployment identity, never a mutable alias."""
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise Refused("missing canonical Pages deployment ID")
        return value
    except (ValueError, TypeError, AttributeError):
        raise Refused("missing canonical Pages deployment ID") from None


def snapshot(client, *, audit=quarantine.audit, public=identity.inspect) -> dict:
    """Validate immutable deployed SHA, bound production proof and guest denial."""
    cfg, hosts, deployed_sha = quarantine.project(client, allow_bound=True)
    if len(hosts) < 2:
        raise Refused("project and immutable alias required")
    # Unlike the DNS quarantine audit, a release requires the independently
    # provisioned production secret, and no bindings on previews.
    try:
        proof.postflight(client, deployed_sha, audit=audit, public=public)
    except (ValueError, OSError):
        raise Refused("Identity proof / public issuer / guest denial unavailable") from None
    canonical = cfg["canonical_deployment"]
    deployment_id = _deployment_id(canonical.get("id"))
    return {
        "source_sha": deployed_sha,
        "deployment_id": deployment_id,
        "aliases": str(len(hosts)),
        "host": readiness.HOST,
        "guest": "denied",
        "production_identity": "proof-bound-unverified",
    }


def preflight(client, live_sha: str, target_sha: str, *,
              audit=quarantine.audit, public=identity.inspect) -> dict:
    """Only a pin of both the currently live SHA and new source is admitted."""
    _sha(live_sha)
    _sha(target_sha)
    if live_sha == target_sha:
        raise Refused("refusing redundant or non-progressing release")
    result = snapshot(client, audit=audit, public=public)
    if result["source_sha"] != live_sha:
        raise Refused("canonical deployment changed; refuse promotion")
    return {
        "prior_deployment_id": result["deployment_id"],
        "prior_source_sha": live_sha,
        "target_source_sha": target_sha,
        "guest": result["guest"],
        "identity": result["production_identity"],
    }


def postflight(client, target_sha: str, previous_id: str, *,
               audit=quarantine.audit, public=identity.inspect) -> dict:
    """Never call a release successful if it changed neither ID nor source."""
    _sha(target_sha)
    _deployment_id(previous_id)
    result = snapshot(client, audit=audit, public=public)
    if result["source_sha"] != target_sha:
        raise Refused("published Pages source SHA mismatch")
    if result["deployment_id"] == previous_id:
        raise Refused("Cloudflare canonical deployment did not advance")
    return {
        "source_sha": target_sha,
        "deployment_id": result["deployment_id"],
        "guest": "denied",
        "aliases": result["aliases"],
        "authenticated_browser": "NOT_VERIFIED",
    }


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("BRIDGESQUAD_RELEASE_PLAN production=protected-dispatch-only "
              "guest=deny authenticated_browser=NOT_VERIFIED")
        return 0
    if len(argv) != 3 or argv[0] not in ("preflight", "postflight"):
        print("Usage: bridgesquad_production_release.py plan|"
              "preflight CURRENT_SHA TARGET_SHA|postflight TARGET_SHA PRIOR_DEPLOYMENT_ID",
              file=sys.stderr)
        return 2
    try:
        client = readiness.CloudflareClient(os.environ)
        if argv[0] == "preflight":
            receipt = preflight(client, argv[1], argv[2])
            for key, value in receipt.items():
                print(f"{key}={value}")
        else:
            receipt = postflight(client, argv[1], argv[2])
            print("BRIDGESQUAD_RELEASE_POSTFLIGHT_OK " +
                  " ".join(f"{key}={value}" for key, value in receipt.items()))
        return 0
    except (Refused, ValueError, OSError, readiness.InventoryError):
        # Deliberately no Cloudflare body, secret value, browser cookie or JWT.
        print("BRIDGESQUAD_RELEASE_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
