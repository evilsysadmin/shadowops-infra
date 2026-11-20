#!/usr/bin/env python3
"""Read-only Cloudflare Pages *historic* alias exposure for ShadowOps games.

Existing game-identity-exposure.py checks canonical FQDNs and main Pages
aliases. This companion enumerates actual immutable/preview deployments from
Cloudflare, then tests anonymous HTTPS access with no cookies or redirects.
It never deletes assets, updates DNS, changes deployments or treats denial
as proof that an authenticated game works.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import urllib.parse

import game_identity_exposure as exposure
from staradvs_pages import AdmissionError, CloudflareClient

PAGE_SIZE = 100
MAX_HOSTS_PER_PROJECT = 28
PATHS = ("/", "/release.json")
WORKERS = 12
ALLOWED_DENIAL = {401, 403, 404}


class InventoryError(Exception):
    pass


def projects():
    return [g for g in exposure.GAMES if g.pages_project is not None]


def main_alias(project: str, hostname: object) -> str:
    if not isinstance(project, str) or not re.fullmatch(r"[a-z0-9-]{3,64}", project):
        raise InventoryError("Pages project not allowlisted")
    if (not isinstance(hostname, str) or
            not re.fullmatch(re.escape(project) + r"(?:-[a-z0-9]+)?\.pages\.dev", hostname)):
        raise InventoryError("Unexpected Pages alias")
    return hostname


def deployment_host(url: object, alias: str) -> str:
    if not isinstance(url, str) or len(url) > 512:
        raise InventoryError("Missing/unsafe Pages deployment URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise InventoryError("Invalid Pages URL") from None
    if (parsed.scheme != "https" or parsed.username or parsed.password or
            port is not None or parsed.path not in ("", "/") or
            parsed.query or parsed.fragment or not parsed.hostname):
        raise InventoryError("Unexpected Pages deployment URL")
    host = parsed.hostname
    if host == alias:
        return host
    if not host.endswith("." + alias):
        raise InventoryError("Foreign Pages deployment hostname")
    prefix = host[:-(len(alias) + 1)]
    if not re.fullmatch(r"[a-z0-9-]{1,63}", prefix):
        raise InventoryError("Unsafe Pages deployment subdomain")
    return host


def list_hosts(client, game) -> tuple[list[str], bool]:
    project = game.pages_project
    path = f"/accounts/{client.account}/pages/projects/{project}"
    status, obj = client.request("GET", path)
    if status == 404:
        raise InventoryError("Pages project not deployed")
    if status != 200 or not isinstance(obj, dict):
        raise InventoryError("Unreadable Pages project")
    if (obj.get("name") != project or obj.get("production_branch") != "main" or
            obj.get("source")):
        raise InventoryError("Foreign Pages source/project")
    alias = main_alias(project, obj.get("subdomain"))
    domains = obj.get("domains") or []
    if (not isinstance(domains, list) or
            any(not isinstance(name, str) or name not in {game.hostname, alias}
                for name in domains)):
        raise InventoryError("Unexpected Pages custom domains")
    hosts = [alias]
    for name in ("latest_deployment", "canonical_deployment"):
        row = obj.get(name)
        if row is not None:
            if not isinstance(row, dict):
                raise InventoryError("Malformed Pages deployment metadata")
            candidate = deployment_host(row.get("url"), alias)
            if candidate not in hosts:
                hosts.append(candidate)

    # The Cloudflare Pages live endpoint returned HTTP 400 to the explicit
    # page=1&per_page=100 query across six known owned projects. Request only
    # the documented bare GET endpoint (also used by our rollback inventory).
    # The existing client discards result_info: it cannot prove that this is
    # the final page. Deliberately NEVER certify complete historical coverage.
    status, rows = client.request("GET", path + "/deployments")
    if status != 200 or not isinstance(rows, list) or len(rows) > PAGE_SIZE:
        raise InventoryError("Unreadable Pages deployment history")
    for row in rows:
        if not isinstance(row, dict) or row.get("project_name") not in (None, project):
            raise InventoryError("Foreign Pages history record")
        candidate = deployment_host(row.get("url"), alias)
        if candidate not in hosts:
            hosts.append(candidate)
    return hosts, False


def assess_one(client, game, request_status) -> dict:
    result = {
        "game": game.slug,
        "environment": game.environment,
        "project": game.pages_project,
        "state": "NOT_FULLY_VERIFIED",
        "hosts_discovered": 0,
        "hosts_probed": 0,
        "historic_inventory_complete": False,
        "skipped_hosts": 0,
        "exposed_hosts": [],
        "unverified_hosts": [],
    }
    try:
        hosts, completed = list_hosts(client, game)
    except InventoryError as exc:
        # This exception is generated only by our fixed, sanitized stage labels.
        result["reason"] = str(exc)
        return result
    except AdmissionError as exc:
        # The shared Cloudflare client returns a fixed HTTP-status-only string
        # on GET failures. Never print arbitrary SDK/provider response content.
        match = re.fullmatch(r"Cloudflare GET failed \(HTTP ([45][0-9]{2})\)", str(exc))
        result["reason"] = "provider-http-" + match.group(1) if match else "provider_request_unavailable"
        return result
    except Exception:
        # Never log Cloudflare SDK/HTTP exception content or secret values.
        result["reason"] = "provider_request_unavailable"
        return result
    result["hosts_discovered"] = len(hosts)
    result["historic_inventory_complete"] = completed
    selected = hosts[:MAX_HOSTS_PER_PROJECT]
    result["hosts_probed"] = len(selected)
    result["skipped_hosts"] = len(hosts) - len(selected)

    def observe(pair):
        host, path = pair
        try:
            status = request_status("https://" + host + path, "GET")
        except Exception:
            status = 0
        if type(status) is not int:
            status = 0
        return host, path, status

    targets = [(host, path) for host in selected for path in PATHS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        observations = list(pool.map(observe, targets))
    grouped = {host: [] for host in selected}
    for host, path, status in observations:
        grouped[host].append(status)
    result["exposed_hosts"] = [host for host, codes in grouped.items()
                               if any(code in (200, 206) for code in codes)][:12]
    result["unverified_hosts"] = [host for host, codes in grouped.items()
                                  if any(code not in ALLOWED_DENIAL | {200, 206} for code in codes)][:12]
    if result["exposed_hosts"]:
        result["state"] = "REVIEW_ANONYMOUS_200"
    elif (not completed or result["skipped_hosts"] or result["unverified_hosts"]):
        result["state"] = "NOT_FULLY_VERIFIED"
    else:
        result["state"] = "GUEST_DENIAL_OBSERVED"
    return result


def audit(client, request_status=exposure.fetch_status) -> dict:
    results = [assess_one(client, game, request_status) for game in projects()]
    states = {x["state"] for x in results}
    state = ("REVIEW_ANONYMOUS_200" if "REVIEW_ANONYMOUS_200" in states else
             "NOT_FULLY_VERIFIED" if "NOT_FULLY_VERIFIED" in states else
             "GUEST_DENIAL_OBSERVED")
    return {
        "state": state,
        "pages_projects": len(results),
        "note": "Read-only historical alias probe; NOT a signed-in Identity test",
        "projects": results,
    }


def main(argv):
    if argv != ["audit"]:
        print("Usage: game_identity_pages_history.py audit", file=sys.stderr)
        return 64
    try:
        report = audit(CloudflareClient(os.environ))
    except Exception:
        print("GAME_IDENTITY_PAGES_HISTORY_UNAVAILABLE (provider or runtime)",
              file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return {"REVIEW_ANONYMOUS_200": 1, "NOT_FULLY_VERIFIED": 2,
            "GUEST_DENIAL_OBSERVED": 0}[report["state"]]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
