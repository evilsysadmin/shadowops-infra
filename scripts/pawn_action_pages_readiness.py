#!/usr/bin/env python3
"""Read-only Pawn Action Pages readiness: no DNS, R2 or release mutation."""
from __future__ import annotations

import json
import os
import sys

from cloudflare_control_plane import CloudflareReadClient, InventoryError
from pawn_action_pages import PROJECT, inspect as inspect_pages
from pawn_action_pages_create import ProvisionError, require_empty_deployment_inventory
from pawn_action_locked_pages_deploy import verify_alias


class ReadinessError(ValueError):
    pass


def inspect(reader, verify_locked=verify_alias):
    state = inspect_pages(reader)
    pages, dns, domain = (state.get(k) for k in
                          ("pages", "dns", "custom_domain"))
    if (pages, dns, domain) == ("absent", "absent", "absent"):
        return {"project": PROJECT, "state": "not_reserved",
                "next": "reserve_once", "cloudflareWrites": 0,
                "gameReady": False}
    if (pages, dns, domain) != ("owned", "absent", "absent"):
        raise ReadinessError("Pages DNS/custom domain/ownership outside first-shell phase")

    root = f"/accounts/{reader.account}/pages/projects/{PROJECT}"
    # No env=production filter: even an unseen PREVIEW blocks admission.
    code, deployments = reader.get(root + "/deployments?per_page=2&page=1")
    if code != 200 or not isinstance(deployments, list) or len(deployments) > 1:
        raise ReadinessError("Pages deployment inventory not a single first release")
    if not deployments:
        # Inventory empty is not enough if project latest/canonical says otherwise.
        require_empty_deployment_inventory(reader)
        return {"project": PROJECT, "state": "reserved_empty",
                "next": "deploy_locked_shell_once", "cloudflareWrites": 0,
                "gameReady": False}

    deployment = deployments[0]
    if (not isinstance(deployment, dict) or not isinstance(deployment.get("id"), str)
            or not deployment["id"] or deployment.get("environment") != "production"):
        raise ReadinessError("A preview or unknown deployment cannot be adopted")
    code, project = reader.get(root)
    if code != 200 or not isinstance(project, dict):
        raise ReadinessError("Pages project metadata unreadable")
    for key in ("latest_deployment", "canonical_deployment"):
        value = project.get(key)
        if not isinstance(value, dict) or value.get("id") != deployment["id"]:
            raise ReadinessError("Deployment ID differs from latest/canonical Pages identity")
    receipt = verify_locked(reader)
    if receipt.get("locked") is not True or receipt.get("gameReady") is not False:
        raise ReadinessError("Public Pages alias is not proven deny-only")
    return {"project": PROJECT, "state": "locked_alias_verified",
            "alias": receipt.get("alias"), "checks": receipt.get("checks"),
            "next": "canonical_domain_and_locked_surface_gate",
            "cloudflareWrites": 0, "gameReady": False}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args != ["inspect"]:
        print("Usage: pawn_action_pages_readiness.py inspect", file=sys.stderr)
        return 2
    try:
        result = inspect(CloudflareReadClient(os.environ))
    except (ReadinessError, InventoryError, ProvisionError, ValueError, OSError) as exc:
        print("PAWN_ACTION_PAGES_READINESS_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("PAWN_ACTION_PAGES_READINESS_BLOCKED unexpected error", file=sys.stderr)
        return 1
    print("PAWN_ACTION_PAGES_READINESS " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
