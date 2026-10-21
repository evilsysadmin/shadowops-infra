#!/usr/bin/env python3
"""Daily Chronicles promotion: validated staging SHA -> API -> Pages -> public audit.

GitHub Actions owns credentials and deploys through existing protected workflows.
This orchestrator does not handle OCI, MongoDB, or Cloudflare secrets.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

from chronicles_production_admission import INFRA, SHA, admit, verified_receipt
from chronicles_production_audit import audit as public_audit, check_api, read_release

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
               gate=admit) -> str:
    if not token:
        raise TrainError("read token required")
    if pinned and not SHA.fullmatch(pinned):
        raise TrainError("manual SHA must be full lowercase 40-hex")
    sha = pinned or live()
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise TrainError("live staging SHA invalid")
    # The pinned manual path may target an earlier validated revision.
    # The scheduled path *always* selects what staging actually serves.
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


def receipt_after(sha: str, kind: str, token: str, *,
                  receipt=verified_receipt, sleep=time.sleep) -> None:
    for attempt in range(6):
        if receipt(sha, "production-" + kind, token):
            return
        if attempt < 5:
            sleep(5)
    raise TrainError(kind + " has no trusted production receipt")


def run(token: str, pinned: str = "", *, select=select_sha,
        current=deployed_sha, start=dispatch, wait=wait_run,
        receipt=receipt_after, verify=public_audit) -> dict:
    sha = select(token, pinned)
    if current(sha, token):
        print("CHRONICLES_TRAIN_NO_CHANGE sha=" + sha)
        return {"source_sha": sha, "result": "unchanged", "api_run": None,
                "pages_run": None}
    api_run = start("api", sha, token)
    wait("api", api_run, token)
    receipt(sha, "api", token)
    # Absolutely no Pages dispatch if the new API isn't publicly ready.
    if not all(check_api(p) for p in ("health", "ready", "cors")):
        raise TrainError("production API public smoke failed after API deployment")
    pages_run = start("pages", sha, token)
    wait("pages", pages_run, token)
    receipt(sha, "pages", token)
    if verify(token) != sha:
        raise TrainError("public production release does not match admitted SHA")
    print("CHRONICLES_TRAIN_PROMOTED sha=" + sha, flush=True)
    return {"source_sha": sha, "result": "promoted", "api_run": api_run,
            "pages_run": pages_run}


def main() -> int:
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != INFRA
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") not in
               ("schedule", "workflow_dispatch")):
            raise TrainError("release train must run on infra main")
        token = os.environ.get("GH_TOKEN", "")
        result = run(token, os.environ.get("CHRONICLES_TRAIN_SOURCE_SHA", "").strip())
        out = Path(os.environ["RUNNER_TEMP"]) / "chronicles-production-train.json"
        out.write_text(json.dumps({"schema": 1, **result}, indent=2) + "\n")
    except (TrainError, urllib.error.URLError, ValueError, TypeError, OSError,
            TimeoutError) as exc:
        # The error type/short message contains no API body, token or secret.
        if isinstance(exc, TrainError):
            print("CHRONICLES_TRAIN_BLOCKED " + str(exc), file=sys.stderr)
        else:
            print("CHRONICLES_TRAIN_BLOCKED provider evidence unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
