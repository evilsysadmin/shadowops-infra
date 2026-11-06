#!/usr/bin/env python3
"""Manual, create-once reservation of an EMPTY dedicated Pawn Action Pages project.

Does not deploy Workers, attach DNS or domains, enable Identity, publish R2
or claim an empty project to be a verified staging application.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Mapping
from cloudflare_control_plane import API, CloudflareReadClient, InventoryError
from pawn_action_pages import HOST, PROJECT, inspect, pages_target

ACCOUNT = re.compile(r"[a-f0-9]{32}\Z")
WRITE_TOKEN = "PAWN_ACTION_PAGES_PROVISION_TOKEN"

class ProvisionError(ValueError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class PagesCreator:
    def __init__(self, env: Mapping[str, str]):
        self.account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        self.token = env.get(WRITE_TOKEN, "").strip()
        read_token = env.get("CLOUDFLARE_API_TOKEN", "").strip()
        if not ACCOUNT.fullmatch(self.account):
            raise ProvisionError("Exact Cloudflare account required")
        if not self.token or not read_token or self.token == read_token:
            raise ProvisionError("Distinct Pages write and inventory read credentials required")

    def create_project(self):
        request = urllib.request.Request(
            f"{API}/accounts/{self.account}/pages/projects",
            data=json.dumps({"name": PROJECT, "production_branch": "main"},
                            separators=(",", ":")).encode(),
            method="POST",
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
                if response.status != 200:
                    raise ProvisionError("Pages creation status unverified")
                raw = response.read(32769)
        except urllib.error.HTTPError as exc:
            raise ProvisionError("Pages create rejected (HTTP " + str(exc.code) + ")") from None
        except ProvisionError:
            raise
        except Exception:
            raise ProvisionError("Pages creation outcome unknown; re-inventory before retry") from None
        if len(raw) > 32768:
            raise ProvisionError("Pages creation response too large")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ProvisionError("Invalid Pages create JSON") from None
        if not isinstance(body, dict) or body.get("success") is not True:
            raise ProvisionError("Pages create not confirmed")
        result = body.get("result")
        if (not isinstance(result, dict) or result.get("name") != PROJECT
                or result.get("production_branch") != "main" or result.get("source")
                or result.get("canonical_deployment") is not None
                or result.get("latest_deployment") is not None):
            raise ProvisionError("Created Pages project has foreign identity or deployment")
        try:
            target = pages_target(result)
        except InventoryError:
            raise ProvisionError("Pages project assigned wrong subdomain") from None
        domains = result.get("domains")
        if (not isinstance(domains, list) or
                any(not isinstance(x, str) or x != target for x in domains)):
            raise ProvisionError("Pages project unexpectedly has custom domains")
        return result

def require_empty_deployment_inventory(reader):
    """No Pages preview/production release, even under the public pages.dev alias.

    Domain ownership alone cannot prove an empty project. Cloudflare exposes
    both the latest deployments on the project and the full preview/production
    deployment inventory via a separate endpoint. A one-item first page is
    enough to disprove emptiness; an unexpected result fails closed.
    """
    root = f"/accounts/{reader.account}/pages/projects/{PROJECT}"
    status, project = reader.get(root)
    if status != 200 or not isinstance(project, dict):
        raise ProvisionError("Cannot inspect Pages project before claiming it empty")
    if (project.get("name") != PROJECT or project.get("production_branch") != "main"
            or project.get("source") is not None
            or "latest_deployment" not in project
            or "canonical_deployment" not in project):
        raise ProvisionError("Pages project identity or deployment metadata unverified")
    if project["latest_deployment"] is not None or project["canonical_deployment"] is not None:
        raise ProvisionError("Pages project already has a production or preview deployment")
    # Query without env=production: the result covers BOTH production and
    # preview. Never accept a Pages project with even one previous deployment.
    status, deployments = reader.get(root + "/deployments?per_page=1&page=1")
    if status != 200 or not isinstance(deployments, list) or deployments:
        raise ProvisionError("Pages deployment inventory not proven empty")


def reserve_once(reader, creator, confirm):
    if confirm != PROJECT:
        raise ProvisionError("Exact project confirmation required")
    if (not ACCOUNT.fullmatch(getattr(reader, "account", ""))
            or getattr(creator, "account", None) != reader.account):
        raise ProvisionError("Reader and writer Cloudflare account mismatch")
    before = inspect(reader)
    keys = ("pages", "dns", "custom_domain")
    state = tuple(before.get(k) for k in keys)
    if state == ("owned", "absent", "absent"):
        require_empty_deployment_inventory(reader)
        return {"project": PROJECT, "state": "already_reserved_unrouted",
                "published": False}
    if state != ("absent", "absent", "absent"):
        raise ProvisionError("Existing Pages/DNS state is not safe for reservation")
    creator.create_project()  # Exactly one POST; no retry and no rollback.
    after = inspect(reader)
    if tuple(after.get(k) for k in keys) != ("owned", "absent", "absent"):
        raise ProvisionError("Pages reservation not verified; re-inventory manually")
    require_empty_deployment_inventory(reader)
    return {"project": PROJECT, "state": "reserved_unrouted", "published": False}

def main(argv=None, env=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "reserve"))
    parser.add_argument("--confirm-project", default="")
    args = parser.parse_args(argv)
    if args.action == "plan":
        print("PAWN_ACTION_PAGES_RESERVATION_PLAN " + json.dumps({
            "project": PROJECT, "host": HOST, "productionBranch": "main",
            "writes": 0, "deploysWorker": False, "createsDns": False}, sort_keys=True))
        return 0
    env = os.environ if env is None else env
    try:
        if args.confirm_project != PROJECT:
            raise ProvisionError("Exact --confirm-project required")
        creator = PagesCreator(env)
        reader = CloudflareReadClient(env)
        outcome = reserve_once(reader, creator, args.confirm_project)
    except (ProvisionError, InventoryError) as exc:
        print("PAWN_ACTION_PAGES_RESERVATION_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("PAWN_ACTION_PAGES_RESERVATION_BLOCKED: unexpected error", file=sys.stderr)
        return 1
    print("PAWN_ACTION_PAGES_RESERVATION_VERIFIED " + json.dumps(outcome, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
