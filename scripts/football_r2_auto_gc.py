#!/usr/bin/env python3
"""Fail-closed, capacity-triggered GC for admitted Football staging releases.

This is called *inside* the existing single-writer Pages publisher, after
source/artifact/owner/keeper preflight but before the first R2 PUT.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request

import football_delivery as delivery
import football_pages as pages
import football_r2_gc as gc

# No unattended garbage collection on forks, PRs or operator laptops.
ALLOWED_EVENTS = {"push", "schedule", "workflow_dispatch"}
DEPLOY_HOST_RE = re.compile(r"[a-z0-9-]{6,64}\.football-staging(?:-[a-z0-9]+)?\.pages\.dev\Z")
MAX_OBJECTS = 150
MAX_RELEASES = 20


class AutoGCError(gc.GCError):
    pass


def permitted():
    if (os.getenv("FOOTBALL_AUTO_GC") != "1"
        or os.getenv("GITHUB_REPOSITORY") != "evilsysadmin/shadowops-infra"
        or os.getenv("GITHUB_REF") != "refs/heads/main"
        or os.getenv("GITHUB_EVENT_NAME") not in ALLOWED_EVENTS):
        raise AutoGCError("Automatic GC requires trusted Infra main publisher")


def read_immutable_manifest(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not DEPLOY_HOST_RE.fullmatch(parsed.hostname or "") or parsed.port is not None or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise AutoGCError("Historical Pages URL is outside owned Football project")
    # Compare with Cloudflare's *actual* owned Pages project subdomain. A
    # lookalike *.pages.dev hostname is never an allowed history source.
    if not parsed.hostname.endswith("." + pages.dns_target()):
        raise AutoGCError("Historical Pages host is not under Football project")
    request = urllib.request.Request(url.rstrip("/") + "/release.json",
                                     headers={**delivery.PUBLIC_HEADERS, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status != 200 or response.geturl() != request.full_url:
                raise AutoGCError("Historical immutable Pages redirect or unexpected response")
            result = json.loads(response.read(65536))
    except (OSError, ValueError) as exc:
        raise AutoGCError("Cannot verify historical immutable Pages release") from exc
    return gc.live_pointer(lambda: result)


def successful_history(reader=pages.request):
    # env=production means Pages' *main branch*, not the ShadowOps prod domain.
    query = urllib.parse.urlencode({"env": "production", "per_page": 50, "page": 1})
    status, records = reader("GET", pages.project_path() + "/deployments?" + query)
    if status != 200 or not isinstance(records, list):
        raise AutoGCError("Cannot enumerate exact Football staging Pages deployments")
    if not records or len(records) > 50:
        raise AutoGCError("No bounded Pages release history")
    valid = []
    for entry in records:
        if not isinstance(entry, dict):
            raise AutoGCError("Malformed Pages deployment")
        trigger = entry.get("deployment_trigger")
        stage = entry.get("latest_stage")
        if not isinstance(trigger, dict) or not isinstance(stage, dict):
            raise AutoGCError("Malformed Pages deployment metadata")
        info = trigger.get("metadata")
        if not isinstance(info, dict):
            raise AutoGCError("Malformed Pages source metadata")
        date, sha = entry.get("created_on"), info.get("commit_hash")
        if (entry.get("environment") != "production"
            or stage.get("status") != "success"
            or info.get("branch") != "main"
            or not isinstance(sha, str) or not delivery.HEX.fullmatch(sha)):
            continue
        if not isinstance(date, str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", date):
            raise AutoGCError("Pages production deployment has no stable timestamp")
        valid.append((date, sha, entry.get("url")))
    return sorted(valid, reverse=True, key=lambda v: v[0])


def pick_rollback(objects, live, *, history=successful_history,
                  fetch_release=read_immutable_manifest):
    groups = gc.group_releases(objects)
    for _, sha, url in history():
        if sha == live["source_sha"]:
            continue
        # A rollback must have its own immutable Pages URL. Never make up a
        # rollback from a partial R2 upload or unverified orphan.
        if not isinstance(url, str):
            continue
        try:
            candidate = fetch_release(url)
        except (gc.GCError, OSError, ValueError):
            continue
        rid = candidate["release"]
        if candidate["source_sha"] != sha or rid == live["release"]:
            continue
        try:
            gc.required_complete(groups.get(rid), rid)
        except gc.GCError:
            continue
        if any(groups[rid].get(gc.ROOT + rid + "/" + name) != info["bytes"]
               for name, info in candidate["files"].items()):
            continue
        return rid
    raise AutoGCError("No independently verified previous Pages runtime; nothing deleted")


def exceeds_budget(objects, additions):
    projected = sum(objects.values()) + sum(size - objects.get(key, 0)
                                              for key, size in additions.items())
    football = sum(size for key, size in objects.items()
                   if key.startswith(delivery.PREFIX + "/"))
    football += sum(size - objects.get(key, 0) for key, size in additions.items())
    return projected > delivery.BUDGET or football > delivery.FOOTBALL_BUDGET


def reclaim_if_needed(account, additions, *, source_sha,
                      inventory=delivery.inventory, live_reader=gc.live_pointer,
                      rollback_picker=pick_rollback,
                      delete_object=None):
    permitted()
    if not delivery.HEX.fullmatch(source_sha):
        raise AutoGCError("Source SHA is not admitted")
    if not exceeds_budget(inventory(account), additions):
        print("FOOTBALL_R2_AUTO_GC_NOT_REQUIRED")
        return False
    # A main fast-forward during admission is not permission to delete.
    if delivery.github(f"/repos/{delivery.REPO}/commits/main").get("sha") != source_sha:
        raise AutoGCError("Football main advanced before automatic cleanup")

    live = live_reader()
    objects = inventory(account)
    if not exceeds_budget(objects, additions):
        print("FOOTBALL_R2_AUTO_GC_NOT_REQUIRED")
        return False
    rollback = rollback_picker(objects, live)
    plan = gc.make_plan(objects, live, rollback)

    # No destructive operation unless the *whole* incoming validated release
    # fits after pruning. Never delete on a hopeless budget shortfall.
    remaining = dict(objects)
    for key, _ in plan["delete"]:
        remaining.pop(key)
    if exceeds_budget(remaining, additions):
        raise AutoGCError("Still above R2 quota after cleanup; no deletion authorized")
    if (not plan["delete"] or len(plan["delete"]) > MAX_OBJECTS
        or len([r for r in plan["releases"] if not r["retained"]]) > MAX_RELEASES):
        raise AutoGCError("No bounded obsolete objects available")
    if any(key in additions for key, _ in plan["delete"]):
        raise AutoGCError("Candidate runtime would be deleted; refusing GC")
    print("FOOTBALL_R2_AUTO_GC_APPROVED " + json.dumps({
        "active": plan["active"], "rollback": rollback,
        "objects": len(plan["delete"]), "bytes": plan["reclaim_bytes"],
        "source_sha": source_sha, "plan_sha256": plan["digest"],
    }, sort_keys=True))

    # Reuse the identical operator-reviewed, immutable plan/digest algorithm.
    gc.delete_plan(plan, objects, live, plan["digest"],
                   refresh_live=live_reader,
                   refresh_inventory=lambda: inventory(account),
                   delete_object=delete_object or (lambda key: gc.r2_delete(account, key)))
    # The publisher separately rechecks the post-GC quota before its first PUT.
    print("FOOTBALL_R2_AUTO_GC_VERIFIED reclaimed_bytes=" + str(plan["reclaim_bytes"]))
    return True


def read_only_probe():
    """Validate historical rollback proof without authorizing DELETE."""
    permitted()
    account = pages.required("CLOUDFLARE_ACCOUNT_ID")
    if not gc.ACCOUNT_ID.fullmatch(account):
        raise AutoGCError("Exact Cloudflare account ID required")
    objects = delivery.inventory(account)
    live = gc.live_pointer()
    rollback = pick_rollback(objects, live)
    plan = gc.make_plan(objects, live, rollback)
    print("FOOTBALL_R2_AUTO_GC_ROLLBACK_PROVEN " + json.dumps({
        "active": plan["active"], "rollback": rollback,
        "obsolete_objects": len(plan["delete"]), "potential_reclaim_bytes": plan["reclaim_bytes"],
    }, sort_keys=True))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] != "probe":
        raise SystemExit("Only read-only 'probe' command exists")
    try:
        read_only_probe()
    except (AutoGCError, gc.GCError, delivery.DeliveryError, OSError, RuntimeError) as error:
        print("FOOTBALL_R2_AUTO_GC_PROBE_BLOCKED " + str(error), file=sys.stderr)
        raise SystemExit(1)
