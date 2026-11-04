#!/usr/bin/env python3
"""Fail-closed, capacity-triggered GC for admitted Football staging releases.

This is called *inside* the existing single-writer Pages publisher, after
source/artifact/owner/keeper preflight but before the first R2 PUT.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import zipfile
from pathlib import PurePosixPath
import urllib.error
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
    except urllib.error.HTTPError as exc:
        raise AutoGCError("Historical Pages release HTTP " + str(exc.code)) from None
    except (OSError, ValueError) as exc:
        raise AutoGCError("Cannot verify historical immutable Pages release") from exc
    return gc.live_pointer(lambda: result)


def attested_source_release(sha, *, github=delivery.github, download=None):
    """Recover historical runtime identity from its CI-attested source artifact.

    Cloudflare Pages can remove old immutable /release.json URLs (404) while
    retaining successful deployment metadata. Trust only the original source
    SHA's passing push CI + immutable artifact digest, never R2 ordering.
    """
    if not isinstance(sha, str) or not delivery.HEX.fullmatch(sha):
        raise AutoGCError("Historical source SHA invalid")
    query = urllib.parse.urlencode({"head_sha": sha, "branch": "main",
                                    "event": "push", "per_page": 20})
    runs = github(f"/repos/{delivery.REPO}/actions/workflows/{delivery.WORKFLOW}/runs?" + query)
    if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
        raise AutoGCError("Historical source CI evidence unavailable")
    needed = {"Football · required visual gate", "Real Chromium · Godot Web boot",
              "Manager · deterministic career and save isolation", "validate"}
    for run in runs["workflow_runs"]:
        if (run.get("head_sha") != sha or run.get("head_branch") != "main"
            or run.get("event") != "push" or run.get("status") != "completed"
            or run.get("conclusion") != "success" or type(run.get("id")) is not int):
            continue
        rid = run["id"]
        jobs = github(f"/repos/{delivery.REPO}/actions/runs/{rid}/jobs?per_page=100").get("jobs")
        if not isinstance(jobs, list):
            raise AutoGCError("Historical source jobs unavailable")
        passed = {j.get("name") for j in jobs if isinstance(j, dict)
                  and j.get("conclusion") == "success" and j.get("completed_at")}
        if not needed <= passed:
            continue
        artifacts = github(f"/repos/{delivery.REPO}/actions/runs/{rid}/artifacts?per_page=100").get("artifacts")
        if not isinstance(artifacts, list):
            raise AutoGCError("Historical source artifacts unavailable")
        matches = [a for a in artifacts if isinstance(a, dict)
                   and a.get("name") == "football-staging-" + sha
                   and a.get("expired") is False and type(a.get("id")) is int
                   and isinstance(a.get("digest"), str)
                   and re.fullmatch(r"sha256:[a-f0-9]{64}", a["digest"])]
        if len(matches) != 1:
            continue
        artifact = matches[0]
        if download is None:
            try:
                proc = subprocess.run(["gh", "api",
                                       f"repos/{delivery.REPO}/actions/artifacts/{artifact['id']}/zip"],
                                      check=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=90)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise AutoGCError("Cannot download signed GitHub historical release artifact") from exc
            blob = proc.stdout
        else:
            blob = download(artifact["id"])
        if (not isinstance(blob, bytes) or len(blob) > 40_000_000
            or hashlib.sha256(blob).hexdigest() != artifact["digest"][7:]):
            raise AutoGCError("Historical artifact ZIP digest mismatch or exceeds bound")
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                names = {item.filename for item in archive.infolist() if not item.is_dir()}
                if (len(names) != len([i for i in archive.infolist() if not i.is_dir()])
                    or len(names) > 401 or "delivery.json" not in names
                    or "web/release.json" not in names):
                    raise AutoGCError("Malformed historical artifact archive")
                manifest = json.loads(archive.read("delivery.json"))
                if (manifest.get("application") != "football-of-matthias"
                    or manifest.get("environment") != "staging"
                    or manifest.get("source_sha") != sha
                    or not isinstance(manifest.get("files"), dict)
                    or set(manifest["files"]) != names - {"delivery.json"}):
                    raise AutoGCError("Historical delivery manifest mismatch")
                total = 0
                for item in archive.infolist():
                    if item.is_dir() or item.filename == "delivery.json":
                        continue  # The root manifest was parsed above and the whole ZIP is SHA-256 bound.
                    p = PurePosixPath(item.filename)
                    if (p.is_absolute() or ".." in p.parts or
                        stat.S_ISLNK(item.external_attr >> 16)
                        or p.parts[0] not in {"web", "runtime"}):
                        raise AutoGCError("Unsafe historical artifact path")
                    raw = archive.read(item.filename)
                    meta = manifest["files"].get(item.filename)
                    if (not isinstance(meta, dict) or len(raw) != meta.get("bytes")
                        or hashlib.sha256(raw).hexdigest() != meta.get("sha256")):
                        raise AutoGCError("Historical artifact entry digest mismatch")
                    total += len(raw)
                    if total > 200_000_000:
                        raise AutoGCError("Historical artifact exceeds source budget")
                release = json.loads(archive.read("web/release.json"))
                pointer = gc.live_pointer(lambda: release)
                runtime_names = sorted(n[len("runtime/"):] for n in names
                                       if n.startswith("runtime/"))
                runtime_entries = {}
                runtime_hash = hashlib.sha256()
                for name in runtime_names:
                    raw = archive.read("runtime/" + name)
                    runtime_hash.update(name.encode() + b"\0" + raw)
                    runtime_entries[name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                                             "bytes": len(raw)}
                if (pointer["source_sha"] != sha
                    or json.loads(archive.read("web/runtime.json")) != release.get("runtime")
                    or runtime_entries != release["files"]
                    or runtime_hash.hexdigest()[:16] != pointer["release"]):
                    raise AutoGCError("Historical artifact runtime does not match source SHA")
                return pointer
        except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
            raise AutoGCError("Malformed historical source artifact") from exc
    raise AutoGCError("No valid historical main CI and immutable artifact")


def successful_history(reader=pages.request):
    # env=production means Pages' *main branch*, not the ShadowOps prod domain.
    # Default API page avoids a provider HTTP 400 on the oversized list.
    # Filter branch, environment and success locally, fail closed otherwise.
    status, records = reader("GET", pages.project_path() + "/deployments")
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
    print("FOOTBALL_R2_ROLLBACK_HISTORY_RESULT total=" + str(len(records)) + " eligible=" + str(len(valid)))
    return sorted(valid, reverse=True, key=lambda v: v[0])


def pick_rollback(objects, live, *, history=successful_history,
                  fetch_release=read_immutable_manifest,
                  artifact_release=attested_source_release):
    groups = gc.group_releases(objects)
    for _, sha, url in history():
        if sha == live["source_sha"]:
            continue
        print("FOOTBALL_R2_ROLLBACK_CHECK sha=" + sha[:12])
        # A rollback must have its own immutable Pages URL. Never make up a
        # rollback from a partial R2 upload or unverified orphan.
        try:
            if not isinstance(url, str):
                raise AutoGCError("Historical Pages URL absent")
            candidate = fetch_release(url)
        except (gc.GCError, OSError, ValueError) as exc:
            print("FOOTBALL_R2_ROLLBACK_HTTP_UNAVAILABLE sha=" + sha[:12]
                  + " reason=" + str(exc)[:130])
            try:
                candidate = artifact_release(sha)
                print("FOOTBALL_R2_ROLLBACK_ATTESTED sha=" + sha[:12])
            except (gc.GCError, delivery.DeliveryError, OSError, ValueError) as artifact_error:
                print("FOOTBALL_R2_ROLLBACK_REJECT sha=" + sha[:12]
                      + " reason=" + str(artifact_error)[:130])
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
