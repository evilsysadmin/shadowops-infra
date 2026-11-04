#!/usr/bin/env python3
"""Manual, fail-closed GC for *obsolete* immutable Football staging runtimes.

Never touches an active release, an explicitly retained rollback, other R2
prefixes, or any release while the live pointer / inventory is changing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.parse

import football_delivery as delivery
import football_pages as pages

RELEASE_ID = re.compile(r"[0-9a-f]{16}\Z")
PLAN_HASH = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT_ID = re.compile(r"[0-9a-f]{32}\Z")
FILE_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
REQUIRED = {"index.html", "index.js", "index.wasm", "index.pck"}
ROOT = delivery.PREFIX + "/releases/"

class GCError(ValueError):
    pass


def live_pointer(reader=delivery.public_release):
    """Obtain a verified, fail-closed, live *staging* release pointer."""
    release = reader()
    if not isinstance(release, dict):
        raise GCError("Public staging release is unavailable")
    runtime = release.get("runtime")
    if not isinstance(runtime, dict):
        raise GCError("No public runtime pointer")
    rid, sha = runtime.get("release"), runtime.get("sourceSha")
    if (release.get("application") != "football-of-matthias"
        or release.get("environment") != "staging"
        or release.get("authentication") != delivery.AUTHENTICATION
        or release.get("source_sha") != sha
        or not isinstance(sha, str) or not delivery.HEX.fullmatch(sha)
        or runtime.get("version") != 1
        or not isinstance(rid, str) or not RELEASE_ID.fullmatch(rid)
        or runtime.get("index") != f"{delivery.CDN}/{ROOT}{rid}/index.html"):
        raise GCError("Untrusted public release identity")
    files = release.get("files")
    if (not isinstance(files, dict) or not REQUIRED <= set(files)
        or any(not isinstance(name, str) or not name or
               not all(FILE_NAME.fullmatch(p) and p not in {".", ".."}
                       for p in name.split("/"))
               or not isinstance(info, dict)
               or type(info.get("bytes")) is not int or info["bytes"] < 0
               for name, info in files.items())):
        raise GCError("Malformed live runtime manifest")
    return {"release": rid, "source_sha": sha, "files": files}


def group_releases(objects):
    if not isinstance(objects, dict):
        raise GCError("Complete R2 inventory required")
    groups = {}
    for key, size in objects.items():
        if not isinstance(key, str) or type(size) is not int or size < 0:
            raise GCError("Malformed R2 object")
        if not key.startswith(ROOT):
            continue  # Never touch shared assets, other games, or Football atlases
        suffix = key[len(ROOT):]
        release, sep, name = suffix.partition("/")
        if (not sep or not RELEASE_ID.fullmatch(release)
            or not name or not all(FILE_NAME.fullmatch(p) and p not in {".", ".."}
                                    for p in name.split("/"))):
            raise GCError("Unrecognized object inside Football release namespace")
        groups.setdefault(release, {})[key] = size
    return groups


def required_complete(group, rid):
    if not group or not REQUIRED <= {key[len(ROOT + rid + "/"):] for key in group}:
        raise GCError("Protected release is absent or incomplete: " + rid)


def make_plan(objects, live, rollback=""):
    groups = group_releases(objects)
    active = live["release"]
    required_complete(groups.get(active), active)
    for name, info in live["files"].items():
        if groups[active].get(ROOT + active + "/" + name) != info["bytes"]:
            raise GCError("Live manifest and R2 inventory disagree")
    if rollback:
        if (not RELEASE_ID.fullmatch(rollback) or rollback == active):
            raise GCError("Rollback must be a distinct 16-hex release ID")
        required_complete(groups.get(rollback), rollback)
    candidates = sorted((key, size) for rid, items in groups.items()
                        if rid not in {active, rollback}
                        for key, size in items.items()) if rollback else []
    snapshot = {
        "version": 1,
        "active": active,
        "source_sha": live["source_sha"],
        "rollback": rollback,
        "inventory": sorted(objects.items()),
        "delete": candidates,
    }
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    return {
        "active": active,
        "source_sha": live["source_sha"],
        "rollback": rollback or None,
        "releases": [{"id": rid, "objects": len(items), "bytes": sum(items.values()),
                      "retained": rid == active or rid == rollback}
                     for rid, items in sorted(groups.items())],
        "delete": candidates,
        "reclaim_bytes": sum(size for _, size in candidates),
        "digest": digest,
    }


def delete_plan(plan, objects, live, expected, *,
                refresh_live=live_pointer, refresh_inventory=None,
                delete_object=None):
    if (not isinstance(expected, str) or not PLAN_HASH.fullmatch(expected)
        or expected != plan["digest"] or not plan["rollback"]
        or not plan["delete"]):
        raise GCError("Explicit matching dry-run digest and rollback required")
    if refresh_inventory is None or delete_object is None:
        raise GCError("Independent inventory and delete functions required")
    if refresh_live() != live or refresh_inventory() != objects:
        raise GCError("Live pointer or complete R2 inventory changed; re-plan")
    for key, _ in plan["delete"]:
        if not key.startswith(ROOT):
            raise GCError("Out-of-scope delete forbidden")
        # Recheck the active release between every mutation, including after a
        # successful deletion, to avoid deleting under a concurrent new deploy.
        if refresh_live() != live:
            raise GCError("Live pointer changed while deleting; stop")
        delete_object(key)
    after = refresh_inventory()
    if any(key in after for key, _ in plan["delete"]):
        raise GCError("R2 deletion did not remove all planned objects")
    if refresh_live() != live:
        raise GCError("Live pointer changed during GC; inspect before proceeding")
    return sum(size for _, size in plan["delete"])


def r2_delete(account, key):
    # REST R2 object delete, NOT bucket delete. Slash separators stay literal.
    if not key.startswith(ROOT):
        raise GCError("Out-of-scope delete forbidden")
    url = (f"/accounts/{account}/r2/buckets/{delivery.BUCKET}/objects/"
           + urllib.parse.quote(key, safe="/-._~"))
    response = delivery.r2_request("DELETE", url)
    result = response.get("result")
    if not isinstance(result, dict) or result.get("key") not in {None, key}:
        raise GCError("R2 did not confirm the requested object")


def run(action, rollback="", expected=""):
    if action not in {"plan", "delete"}:
        raise GCError("Only plan and delete actions exist")
    event = os.environ.get("GITHUB_EVENT_NAME")
    if (os.environ.get("GITHUB_REF") != "refs/heads/main"
        or event not in {"push", "workflow_dispatch"}
        or (action == "delete" and event != "workflow_dispatch")):
        raise GCError("Only main read-only plan or manual main deletion is allowed")
    account = pages.required("CLOUDFLARE_ACCOUNT_ID")
    if not ACCOUNT_ID.fullmatch(account):
        raise GCError("Exact Cloudflare account ID required")
    live = live_pointer()
    objects = delivery.inventory(account)
    plan = make_plan(objects, live, rollback)
    print("FOOTBALL_R2_GC_PLAN " + json.dumps({
        "active": plan["active"], "source_sha": plan["source_sha"],
        "rollback": plan["rollback"], "releases": plan["releases"],
        "delete_objects": len(plan["delete"]),
        "reclaim_bytes": plan["reclaim_bytes"],
        "plan_sha256": plan["digest"],
    }, sort_keys=True))
    if action == "plan":
        return
    if os.environ.get("FOOTBALL_GC_CONFIRM") != "delete":
        raise GCError("Explicit delete confirmation required")
    reclaimed = delete_plan(plan, objects, live, expected,
                            refresh_inventory=lambda: delivery.inventory(account),
                            delete_object=lambda key: r2_delete(account, key))
    print(f"FOOTBALL_R2_GC_VERIFIED objects={len(plan['delete'])} reclaimed_bytes={reclaimed}")


if __name__ == "__main__":
    try:
        run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "",
            sys.argv[3] if len(sys.argv) > 3 else "")
    except (GCError, delivery.DeliveryError, RuntimeError, KeyError, TypeError) as error:
        print("FOOTBALL_R2_GC_BLOCKED " + str(error), file=sys.stderr)
        raise SystemExit(1)
