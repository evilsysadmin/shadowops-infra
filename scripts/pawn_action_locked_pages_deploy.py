#!/usr/bin/env python3
"""Admit an EMPTY Pawn Action Pages project and verify a locked-only deployment.

The writer is external (manual Wrangler workflow). This CLI makes NO
Cloudflare writes, never accepts a game release, and never claims that the
authenticated private-R2 candidate is ready for deployment.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from cloudflare_control_plane import CloudflareReadClient, InventoryError
from pawn_action_pages import PROJECT, inspect, pages_target
from pawn_action_pages_create import require_empty_deployment_inventory
from pawn_action_pages_shell import (
    SHELL_MARKER_HEADER, SHELL_MARKER_VALUE, verify as verify_shell,
)
from pawn_action_staging_surface import DENIED as LOCKED_PATHS, STATUS as LOCKED_STATUS

ACCOUNT = re.compile(r"[a-f0-9]{32}\Z")
WRITE_TOKEN = "PAWN_ACTION_PAGES_DEPLOY_TOKEN"
# Reuse the complete reviewed fixed canonical-host locked perimeter.
PATHS = (LOCKED_STATUS, *LOCKED_PATHS)


class LockedDeploymentError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def preflight(reader, shell_dir):
    shell = verify_shell(shell_dir)
    if shell["locked"] is not True or shell["gameFiles"] != 0:
        raise LockedDeploymentError("Only the canonical deny-all Pages shell is allowed")
    state = inspect(reader)
    if (state.get("pages") != "owned" or state.get("dns") != "absent"
            or state.get("custom_domain") != "absent"):
        raise LockedDeploymentError("Dedicated empty Pages project/DNS not proven")
    require_empty_deployment_inventory(reader)
    return {"project": PROJECT, "edgeSha256": shell["edgeSha256"],
            "locked": True, "gameFiles": 0, "publishGame": False}


def target_from_reader(reader):
    root = f"/accounts/{reader.account}/pages/projects/{PROJECT}"
    status, project = reader.get(root)
    if (status != 200 or not isinstance(project, dict) or
            project.get("name") != PROJECT or project.get("production_branch") != "main" or
            project.get("source") is not None):
        raise LockedDeploymentError("Unexpected Pages project identity after shell deploy")
    return pages_target(project)


def probe_alias(target, path, method):
    if path not in PATHS or method not in ("GET", "HEAD"):
        raise LockedDeploymentError("Unexpected alias probe target")
    try:
        if not isinstance(target, str) or pages_target({"subdomain": target}) != target:
            raise LockedDeploymentError("Unexpected Pages alias")
    except InventoryError:
        raise LockedDeploymentError("Unexpected Pages alias") from None
    url = "https://" + target + path
    req = urllib.request.Request(url, method=method)
    try:
        try:
            resp = urllib.request.build_opener(NoRedirect()).open(req, timeout=8)
        except urllib.error.HTTPError as exc:
            resp = exc
        with resp:
            status, headers = resp.status, {k.lower(): v.lower() for k, v in resp.headers.items()}
            if (status != 404 or "location" in headers or
                    "no-store" not in headers.get("cache-control", "") or
                    headers.get("x-content-type-options") != "nosniff" or
                    headers.get(SHELL_MARKER_HEADER.lower()) != SHELL_MARKER_VALUE)::
                raise LockedDeploymentError("Pages alias does not prove deny-all Worker on " + path)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LockedDeploymentError("Pages alias not verifiably reachable: " + type(exc).__name__) from None


def verify_alias(reader, probe=probe_alias):
    state = inspect(reader)
    if (state.get("pages") != "owned" or state.get("dns") != "absent" or
            state.get("custom_domain") != "absent"):
        raise LockedDeploymentError("Unrouted Pages project ownership changed")
    target = target_from_reader(reader)
    root = f"/accounts/{reader.account}/pages/projects/{PROJECT}"
    status, deployments = reader.get(root + "/deployments?per_page=1&page=1")
    if (status != 200 or not isinstance(deployments, list) or len(deployments) != 1
            or not isinstance(deployments[0], dict) or not deployments[0].get("id")):
        raise LockedDeploymentError("Expected an identifiable Pages deployment, without public game")
    for path in PATHS:
        for method in ("GET", "HEAD"):
            probe(target, path, method)
    return {"project": PROJECT, "alias": target, "locked": True,
            "gameReady": False, "dnsAttached": False, "checks": 2 * len(PATHS)}


def main(argv=None, env=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "preflight", "verify-alias"))
    parser.add_argument("--shell", type=__import__("pathlib").Path)
    parser.add_argument("--confirm-project", default="")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    if args.action == "plan":
        print("PAWN_ACTION_LOCKED_DEPLOY_PLAN " + json.dumps({
            "project": PROJECT, "automaticWrites": 0, "gameFiles": 0,
            "requiresManualDispatch": True}, sort_keys=True))
        return 0
    try:
        if args.action == "preflight":
            if args.confirm_project != PROJECT or args.shell is None:
                raise LockedDeploymentError("Exact confirmation and canonical shell required")
            read_token = env.get("CLOUDFLARE_API_TOKEN", "")
            write_token = env.get(WRITE_TOKEN, "")
            if (not ACCOUNT.fullmatch(env.get("CLOUDFLARE_ACCOUNT_ID", "")) or
                    not read_token or not write_token or read_token == write_token):
                raise LockedDeploymentError("Distinct read and deploy credentials and exact account required")
            reader = CloudflareReadClient(env)
            result = preflight(reader, args.shell)
        else:
            reader = CloudflareReadClient(env)
            result = verify_alias(reader)
    except (LockedDeploymentError, InventoryError, OSError, ValueError) as exc:
        print("PAWN_ACTION_LOCKED_DEPLOY_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("PAWN_ACTION_LOCKED_DEPLOY_BLOCKED: unexpected error", file=sys.stderr)
        return 1
    print("PAWN_ACTION_LOCKED_DEPLOY_VERIFIED " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
