#!/usr/bin/env python3
"""Fail-closed staging handoff: do not publish a Chronicles client before its API.

Trust only a successful Infra API workflow run on main carrying the exact
source-SHA receipt written after OCI health, public smoke and account E2E.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

INFRA = "evilsysadmin/shadowops-infra"
SOURCE = "evilsysadmin/chronicles-of-matthias"
API_WORKFLOW = ".github/workflows/chronicles-api-staging.yml"
SHA = re.compile(r"^[0-9a-f]{40}$")
API_ORIGIN = "https://chronicles-api-staging.shadowops.dpdns.org/api"


class GateError(RuntimeError):
    pass


def fetch(path: str, token: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise GateError("Cannot read GitHub deployment evidence") from exc
    if not isinstance(result, dict):
        raise GateError("Malformed GitHub evidence")
    return result


def evidence_ok(sha: str, listing: dict, read_run) -> bool:
    if not SHA.fullmatch(sha):
        raise GateError("Invalid source SHA")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list):
        raise GateError("Missing deployment artifacts")
    name = "chronicles-api-staging-" + sha
    for item in artifacts:
        if not isinstance(item, dict) or item.get("name") != name or item.get("expired") is not False:
            continue
        origin = item.get("workflow_run") or {}
        if not isinstance(origin, dict) or origin.get("head_branch") != "main":
            continue
        run_id = origin.get("id")
        if not isinstance(run_id, int) or run_id <= 0:
            continue
        run = read_run(run_id)
        if (
            run.get("id") == run_id
            and run.get("conclusion") == "success"
            and run.get("status") == "completed"
            and run.get("path") == API_WORKFLOW
            and run.get("head_branch") == "main"
            and (run.get("repository") or {}).get("full_name") == INFRA
            and run.get("event") in {"push", "schedule", "workflow_dispatch"}
        ):
            return True
    return False


def api_receipt_available(sha: str, token: str, *, get=fetch) -> bool:
    """Single, trusted exact-SHA receipt check shared by API admission and Pages."""
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing read token or invalid source SHA")
    path = f"repos/{INFRA}/actions/artifacts?" + urllib.parse.urlencode(
        {"name": "chronicles-api-staging-" + sha, "per_page": 100}
    )
    return evidence_ok(
        sha, get(path, token),
        lambda run_id: get(f"repos/{INFRA}/actions/runs/{run_id}", token),
    )


def probe_public(path: str) -> bool:
    """Require real public 2xx responses, not merely a historical deploy receipt."""
    request = urllib.request.Request(
        API_ORIGIN + "/" + path,
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-api-admission/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def public_api_healthy(*, probe=probe_public, sleep=time.sleep) -> bool:
    """Retry each public endpoint once; never redeploy on inconclusive health."""
    for path in ("health", "ready"):
        if probe(path):
            continue
        sleep(2)
        if not probe(path):
            return False
    return True


def wait_for_api(sha: str, token: str, *, attempts: int = 49, sleep=time.sleep, get=fetch) -> None:
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing read token or invalid source SHA")
    for attempt in range(attempts):
        current = get(f"repos/{SOURCE}/commits/main", token).get("sha")
        if current != sha:
            raise GateError("CHRONICLES_PAGES_STALE_SOURCE_BLOCKED")
        if api_receipt_available(sha, token, get=get):
            print("CHRONICLES_API_VERIFIED_BEFORE_PAGES sha=" + sha)
            return
        if attempt + 1 < attempts:
            print("CHRONICLES_API_RECEIPT_PENDING attempt=" + str(attempt + 1), flush=True)
            sleep(15)
    raise GateError("CHRONICLES_API_RECEIPT_TIMEOUT")


def main() -> int:
    token = os.environ.get("GH_TOKEN", "")
    if len(sys.argv) == 3 and sys.argv[1] == "--receipt-only":
        try:
            if not api_receipt_available(sys.argv[2], token):
                return 1  # No trusted receipt: normal deploy admission may proceed.
            if not public_api_healthy():
                print("CHRONICLES_API_RECEIPT_LIVE_HEALTH_INCONCLUSIVE", file=sys.stderr)
                return 2  # Do not redeploy automatically on a transient/outage.
            print("CHRONICLES_API_STAGING_ALREADY_VERIFIED sha=" + sys.argv[2])
            return 0
        except GateError as exc:
            print(str(exc), file=sys.stderr)
            return 2  # Inconclusive: do not deploy or falsely claim verification.
    if len(sys.argv) != 2:
        return 64
    try:
        wait_for_api(sys.argv[1], token)
        return 0
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
