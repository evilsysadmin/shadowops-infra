#!/usr/bin/env python3
"""Daily Chronicles promotion: validated staging SHA -> API -> Pages -> public audit.

GitHub Actions owns credentials and deploys through existing protected workflows.
This orchestrator does not handle OCI, MongoDB, or Cloudflare secrets.
"""
from __future__ import annotations

from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

from chronicles_api_before_pages import read_public_build as read_staging_api_build
from chronicles_production_admission import INFRA, SHA, PromotionError, admit, verified_receipt
from chronicles_production_audit import (audit as public_audit, check_api, check_sso_jwks,
                                         probe_https, probe_react_preview, read_release,
                                         read_live_api_build)

STAGING = "https://staging.chronicles.shadowops.dpdns.org/release.json"
API_WORKFLOW = "chronicles-api-staging.yml"
PAGES_WORKFLOW = "chronicles-pages-release.yml"
WORKFLOWS = {"api": API_WORKFLOW, "pages": PAGES_WORKFLOW}


class TrainError(RuntimeError):
    pass


def staging_sha() -> str:
    """Read the exact live build, not whichever commit is newest on main."""
    req = urllib.request.Request(
        STAGING + "?train=" + str(time.time_ns()),
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "ChroniclesReleaseTrain/1"},
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.status != 200 or response.geturl().split("?")[0] != STAGING:
            raise TrainError("staging manifest origin or HTTP status invalid")
        data = json.loads(response.read(4096))
    if not isinstance(data, dict) or not isinstance(data.get("build"), str):
        raise TrainError("staging build manifest invalid")
    return data["build"]


def select_sha(token: str, pinned: str = "", *, live=staging_sha,
               gate=admit, api_build=read_staging_api_build) -> str:
    if not token:
        raise TrainError("read token required")
    if pinned and not SHA.fullmatch(pinned):
        raise TrainError("manual SHA must be full lowercase 40-hex")
    sha = pinned or live()
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise TrainError("live staging SHA invalid")
    # Scheduled/default promotion requires the *current* public staging API
    # and Pages to serve the same source revision at candidate selection time.
    # Historical receipts by themselves cannot prove this live relationship.
    # An explicitly pinned manual rollback/hotfix may target an older admitted
    # SHA and must not depend on what staging currently serves.
    if not pinned and api_build() != sha:
        raise TrainError("staging API live source SHA missing or mismatched")
    gate(sha, token)
    return sha


def deployed_sha(sha: str, token: str, *, manifest=read_release,
                 probe=check_api, receipt=verified_receipt) -> bool:
    """Skip an unchanged healthy version; never overwrite a sick same-SHA prod."""
    current = manifest()
    if not isinstance(current, dict) or not isinstance(current.get("build"), str):
        raise TrainError("production manifest unavailable")
    if current["build"] != sha:
        return False
    if not all(probe(p) for p in ("health", "ready", "cors")):
        raise TrainError("production serves same SHA but API is not healthy")
    if not all(receipt(sha, kind, token)
               for kind in ("production-api", "production-pages")):
        raise TrainError("production serves same SHA without trusted receipts")
    return True


def github_api(method: str, path: str, token: str, data: dict | None = None) -> dict:
    # Fixed GitHub-owned workflow/run family; no caller-provided URL.
    if not path.startswith("repos/" + INFRA + "/actions/"):
        raise TrainError("unexpected GitHub API route")
    if any(segment in ("", ".", "..") for segment in path.split("/")):
        raise TrainError("unsafe GitHub API route")
    req = urllib.request.Request(
        "https://api.github.com/" + path,
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        method=method,
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=25) as response:
        if response.status != 200:
            raise TrainError("GitHub Actions API status not acknowledged")
        result = json.loads(response.read(250000))
    if not isinstance(result, dict):
        raise TrainError("invalid GitHub Actions response")
    return result



DAILY_TRAIN_RUNS = (
    f"repos/{INFRA}/actions/workflows/chronicles-production-train.yml/runs?per_page=30"
)
DAILY_TRAIN_JOB = "Admit staging, promote API, promote Pages, verify public release"
DAILY_TRAIN_STEP = "Promote only admitted source, stop if API/Pages fail"
DAILY_EXTERNAL_TITLE = "Chronicles train · 08:00 Madrid · external-schedule"


def _daily_train_created(run: dict) -> datetime:
    try:
        value = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError("naive run timestamp")
        return value.astimezone(ZoneInfo("Europe/Madrid"))
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise TrainError("invalid daily train timestamp evidence") from exc


def _is_automatic_run(run: dict) -> bool:
    return (
        run.get("path") == ".github/workflows/chronicles-production-train.yml"
        and run.get("head_branch") == "main"
        and (run.get("repository") or {}).get("full_name") == INFRA
        and (run.get("event") == "schedule"
             or (run.get("event") == "workflow_dispatch"
                 and run.get("display_title") == DAILY_EXTERNAL_TITLE))
    )


def previous_daily_train(token: str, current_run_id: int, *, now=None,
                         call=github_api) -> int | None:
    """Read-only exactly-once gate under the workflow's serialized concurrency.

    A second automatic run is a no-op only when the *previous* daily train
    actually ran and passed; failures require human recovery, not retry storms.
    This check is intentionally opt-in until the external scheduler cutover.
    """
    if not token or type(current_run_id) is not int or current_run_id <= 0:
        raise TrainError("invalid daily train identity")
    instant = now if now is not None else datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise TrainError("daily train clock needs timezone")
    local = instant.astimezone(ZoneInfo("Europe/Madrid"))
    payload = call("GET", DAILY_TRAIN_RUNS, token)
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or not runs or len(runs) > 30:
        raise TrainError("incomplete daily train history")
    if any(not isinstance(run, dict) for run in runs):
        raise TrainError("invalid daily train history")
    if len({run.get("id") for run in runs}) != len(runs):
        raise TrainError("duplicate daily train evidence")
    # If pagination truncates the current Madrid day, never guess that no
    # previous automatic train exists.
    if len(runs) == 30 and _daily_train_created(runs[-1]).date() >= local.date():
        raise TrainError("daily train history truncated")
    current = [r for r in runs if r.get("id") == current_run_id]
    if len(current) != 1 or not _is_automatic_run(current[0]):
        raise TrainError("current automatic train identity unavailable")
    created = _daily_train_created(current[0])
    if created.date() != local.date():
        raise TrainError("current daily train not from today")

    earlier = []
    for run in runs:
        if run.get("id") == current_run_id or not _is_automatic_run(run):
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise TrainError("invalid earlier train ID")
        timestamp = _daily_train_created(run)
        if (timestamp.date() != local.date()
                or timestamp.time() < time(7, 45)
                or (run["event"] == "workflow_dispatch"
                    and timestamp.time() > time(8, 15))):
            continue
        if (timestamp, run_id) < (created, current_run_id):
            earlier.append((timestamp, run_id, run))
    if not earlier:
        return None
    # The first attempt is authoritative. No automatic reattempt after a
    # failed, cancelled or incomplete train.
    previous = min(earlier, key=lambda item: (item[0], item[1]))[2]
    if (previous.get("status") != "completed"
            or previous.get("conclusion") != "success"):
        raise TrainError("previous automatic train was not successful")
    run_id = previous["id"]
    jobs = call("GET", f"repos/{INFRA}/actions/runs/{run_id}/jobs?per_page=30",
                token).get("jobs")
    if not isinstance(jobs, list) or len(jobs) > 30:
        raise TrainError("invalid earlier train job evidence")
    matched = [j for j in jobs if isinstance(j, dict)
               and j.get("name") == DAILY_TRAIN_JOB]
    if (len(matched) != 1 or matched[0].get("status") != "completed"
            or matched[0].get("conclusion") != "success"
            or not any(isinstance(step, dict)
                       and step.get("name") == DAILY_TRAIN_STEP
                       and step.get("status") == "completed"
                       and step.get("conclusion") == "success"
                       for step in matched[0].get("steps", []))):
        raise TrainError("previous automatic promotion step unverified")
    return run_id


def dispatch(kind: str, sha: str, token: str, *, call=github_api) -> int:
    if kind not in WORKFLOWS or not SHA.fullmatch(sha):
        raise TrainError("invalid workflow or source SHA")
    inputs = ({"action": "deploy", "environment": "production",
               "source_sha": sha, "only_if_new": "false"} if kind == "api"
              else {"environment": "production", "source_sha": sha,
                    "only_if_new": "false"})
    response = call("POST",
        f"repos/{INFRA}/actions/workflows/{WORKFLOWS[kind]}/dispatches",
        token, {"ref": "main", "inputs": inputs, "return_run_details": True})
    run_id = response.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0:
        raise TrainError("dispatch returned no attributable workflow run ID")
    print(f"CHRONICLES_TRAIN_{kind.upper()}_DISPATCHED run={run_id}", flush=True)
    return run_id


def wait_run(kind: str, run_id: int, token: str, *, call=github_api,
             sleep=time.sleep, attempts: int = 135) -> None:
    if kind not in WORKFLOWS or type(run_id) is not int or run_id <= 0:
        raise TrainError("invalid workflow run")
    for _ in range(attempts):
        run = call("GET", f"repos/{INFRA}/actions/runs/{run_id}", token)
        if (run.get("id") != run_id
            or run.get("path") != ".github/workflows/" + WORKFLOWS[kind]
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main"
            or (run.get("repository") or {}).get("full_name") != INFRA):
            raise TrainError("workflow run identity mismatch")
        if run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise TrainError(f"{kind} production workflow did not succeed (run={run_id})")
            print(f"CHRONICLES_TRAIN_{kind.upper()}_GREEN run={run_id}", flush=True)
            return
        sleep(10)
    raise TrainError(f"{kind} production workflow timed out (run={run_id})")


def receipt_after(sha: str, kind: str, token: str, run_id: int, *,
                  receipt=verified_receipt, sleep=time.sleep) -> None:
    if type(run_id) is not int or run_id <= 0:
        raise TrainError("expected child receipt run ID invalid")
    for attempt in range(6):
        if receipt(sha, "production-" + kind, token,
                   expected_run_id=run_id):
            return
        if attempt < 5:
            sleep(5)
    raise TrainError(kind + " has no trusted production receipt")


def progress_stage(progress: dict | None, stage: str, **changes: object) -> None:
    """In-memory nonsecret evidence; caller persists it even when a gate fails."""
    if progress is not None:
        progress.update(changes)
        progress["stage"] = stage


def production_surface_ready(*, page=probe_https, assets=probe_react_preview,
                             api=check_api, sso=check_sso_jwks) -> bool:
    """Check current production accessibility even when candidate SHA differs.

    Intentionally do not require the *old* production API to expose /release
    or have a receipt for the *new* candidate. This never mutates anything.
    """
    return (page() == "ok"
            and assets(path="/", assets=b"/assets/", manifest_path=None) == "ok"
            and all(api(name) for name in ("health", "ready", "cors"))
            and sso())


def preflight(token: str, pinned: str = "", *, select=select_sha,
              current=deployed_sha, verify=public_audit,
              surface=production_surface_ready,
              progress: dict | None = None) -> dict:
    """Inspect live staging admission and production, without any dispatch/write."""
    progress_stage(progress, "candidate-admission")
    sha = select(token, pinned)
    progress_stage(progress, "production-inspection", source_sha=sha)
    if current(sha, token):
        progress_stage(progress, "public-verification")
        if verify(token) != sha:
            raise TrainError("unchanged production failed public game audit")
        action = "unchanged"
    else:
        # A different SHA is not proof the live production service is healthy.
        # Check its public surface before claiming the candidate is promotable.
        progress_stage(progress, "existing-production-readiness")
        if not surface():
            raise TrainError("current production surface unhealthy before promotion")
        action = "would-promote"
    progress_stage(progress, "completed", result=action)
    print("CHRONICLES_TRAIN_PREFLIGHT " + action + " sha=" + sha, flush=True)
    return {"source_sha": sha, "result": action, "api_run": None,
            "pages_run": None}


def run(token: str, pinned: str = "", *, select=select_sha,
        current=deployed_sha, start=dispatch, wait=wait_run,
        receipt=receipt_after, verify=public_audit,
        probe=check_api, api_build=read_live_api_build,
        scheduled: bool = False, surface=production_surface_ready,
        progress: dict | None = None) -> dict:
    progress_stage(progress, "candidate-admission")
    sha = select(token, pinned)
    progress_stage(progress, "production-inspection", source_sha=sha)
    if current(sha, token):
        # Receipts and API health alone do not prove the JS/CSS still load.
        progress_stage(progress, "public-verification")
        if verify(token) != sha:
            raise TrainError("unchanged production failed public game audit")
        progress_stage(progress, "completed", result="unchanged")
        print("CHRONICLES_TRAIN_NO_CHANGE sha=" + sha)
        return {"source_sha": sha, "result": "unchanged", "api_run": None,
                "pages_run": None}
    # Scheduled promotions are not automatic disaster recovery. If production
    # was already degraded, preserve it and require an explicit human hotfix.
    # Explicit manual promotions may deliberately repair an outage.
    if scheduled:
        progress_stage(progress, "existing-production-readiness")
        if not surface():
            raise TrainError("current production unhealthy before scheduled promotion")
        progress_stage(progress, "existing-production-ready")
    progress_stage(progress, "api-dispatch")
    api_run = start("api", sha, token)
    progress_stage(progress, "api-running", api_run=api_run)
    wait("api", api_run, token)
    progress_stage(progress, "api-green")
    receipt(sha, "api", token, api_run)
    progress_stage(progress, "api-receipt")
    # Absolutely no Pages dispatch if the new API isn't publicly ready.
    if not all(probe(p) for p in ("health", "ready", "cors")):
        raise TrainError("production API public smoke failed after API deployment")
    progress_stage(progress, "api-public-ready")
    if api_build() != sha:
        raise TrainError("production API public source SHA missing or mismatched")
    progress_stage(progress, "api-source-matched")
    pages_run = start("pages", sha, token)
    progress_stage(progress, "pages-running", pages_run=pages_run)
    wait("pages", pages_run, token)
    progress_stage(progress, "pages-green")
    receipt(sha, "pages", token, pages_run)
    progress_stage(progress, "pages-receipt")
    if verify(token) != sha:
        raise TrainError("public production release does not match admitted SHA")
    progress_stage(progress, "completed", result="promoted")
    print("CHRONICLES_TRAIN_PROMOTED sha=" + sha, flush=True)
    return {"source_sha": sha, "result": "promoted", "api_run": api_run,
            "pages_run": pages_run}


def main() -> int:
    # Keep the last known stage and child run IDs even if Pages fails after
    # an API deployment. Never include API responses, credentials or tokens.
    progress: dict = {
        "schema": 1, "result": "blocked", "stage": "starting",
        "source_sha": None, "api_run": None, "pages_run": None,
    }
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != INFRA
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") not in
               ("schedule", "workflow_dispatch")):
            raise TrainError("release train must run on infra main")
        token = os.environ.get("GH_TOKEN", "")
        source_sha = os.environ.get("CHRONICLES_TRAIN_SOURCE_SHA", "").strip()
        dry_run = os.environ.get("CHRONICLES_TRAIN_DRY_RUN", "").lower() == "true"
        automated = (os.environ["GITHUB_EVENT_NAME"] == "schedule"
                     or os.environ.get("CHRONICLES_TRAIN_AUTOMATED", "").lower() == "true")
        if (not dry_run and automated
                and os.environ.get("CHRONICLES_TRAIN_DEDUPE_ENABLED", "").lower() == "true"):
            try:
                run_id = int(os.environ.get("GITHUB_RUN_ID", ""))
            except ValueError as exc:
                raise TrainError("invalid current daily train run ID") from exc
            progress_stage(progress, "daily-duplicate-check")
            previous = previous_daily_train(token, run_id)
            if previous is not None:
                progress_stage(progress, "completed", result="duplicate-skip",
                               previous_run=previous)
                print(f"CHRONICLES_TRAIN_DUPLICATE_SKIPPED previous_run={previous}",
                      flush=True)
                return 0
        result = (preflight(token, source_sha, progress=progress) if dry_run
                  else run(token, source_sha,
                           scheduled=automated,
                           progress=progress))
        progress.update(result)
        return 0
    except (TrainError, PromotionError, urllib.error.URLError, ValueError,
            TypeError, OSError, TimeoutError) as exc:
        # The error type/short message contains no API body, token or secret.
        progress["result"] = "blocked"
        if isinstance(exc, TrainError):
            print("CHRONICLES_TRAIN_BLOCKED " + str(exc), file=sys.stderr)
        else:
            print("CHRONICLES_TRAIN_BLOCKED provider evidence unavailable", file=sys.stderr)
        return 1
    finally:
        # upload-artifact has if: always(). Do not replace the original gate
        # failure with a journal-write error when the runner disk is full.
        directory = os.environ.get("RUNNER_TEMP")
        if directory:
            try:
                out = Path(directory) / "chronicles-production-train.json"
                out.write_text(json.dumps(progress, indent=2) + "\n")
            except (OSError, TypeError, ValueError):
                print("CHRONICLES_TRAIN_JOURNAL_UNAVAILABLE", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
