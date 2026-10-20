#!/usr/bin/env python3
"""Skip a staging Pages deployment only when its receipt AND live HTTPS build agree."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from chronicles_api_before_pages import GateError, INFRA, SHA, fetch

PAGES_WORKFLOW = ".github/workflows/chronicles-pages-release.yml"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"


def receipt_ok(sha: str, listing: dict, read_run) -> bool:
    if not SHA.fullmatch(sha):
        raise GateError("Invalid Chronicles source SHA")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list):
        raise GateError("Malformed Pages artifact listing")
    expected = "chronicles-pages-staging-" + sha
    for item in artifacts:
        if not isinstance(item, dict) or item.get("name") != expected or item.get("expired") is not False:
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
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("path") == PAGES_WORKFLOW
            and run.get("head_branch") == "main"
            and (run.get("repository") or {}).get("full_name") == INFRA
            and run.get("event") in {"push", "schedule", "workflow_dispatch"}
        ):
            return True
    return False


def read_manifest(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-pages-receipt/1"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def verified_live(sha: str, token: str, *, get=fetch, public=read_manifest) -> bool:
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing token or invalid Chronicles source SHA")
    path = "repos/" + INFRA + "/actions/artifacts?" + urllib.parse.urlencode(
        {"name": "chronicles-pages-staging-" + sha, "per_page": 100}
    )
    if not receipt_ok(sha, get(path, token),
                      lambda run_id: get(f"repos/{INFRA}/actions/runs/{run_id}", token)):
        return False
    url = ORIGIN + "/release.json?receipt_check=" + str(time.time_ns())
    try:
        manifest = public(url)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False  # Cannot claim already verified when live Pages is unavailable.
    return isinstance(manifest, dict) and manifest.get("build") == sha


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    try:
        if verified_live(sys.argv[1], os.environ.get("GH_TOKEN", "")):
            print("CHRONICLES_PAGES_ALREADY_VERIFIED sha=" + sys.argv[1])
            return 0
        print("CHRONICLES_PAGES_RECEIPT_MISSING_OR_LIVE_DRIFT sha=" + sys.argv[1])
        return 1
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
