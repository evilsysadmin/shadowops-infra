#!/usr/bin/env python3
"""Read-only production promotion gate for the exact Chronicles staging generation.

Two successful, trusted Infra receipts (API and playable Pages) plus source
CI on protected main are mandatory. No Cloudflare/OCI mutation happens here.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from chronicles_source_ci import inspect as inspect_source_ci

INFRA = "evilsysadmin/shadowops-infra"
SOURCE = "evilsysadmin/chronicles-of-matthias"
SHA = re.compile(r"^[0-9a-f]{40}$")
RECEIPTS = {
    "api": (".github/workflows/chronicles-api-staging.yml", "chronicles-api-staging-"),
    "pages": (".github/workflows/chronicles-pages-release.yml", "chronicles-pages-staging-"),
    "production-api": (".github/workflows/chronicles-api-staging.yml", "chronicles-api-production-"),
}


class PromotionError(RuntimeError):
    pass


def github_read(path: str, token: str) -> dict:
    if not path.startswith("repos/") or any(segment in {".", ".."} for segment in path.partition("?")[0].split("/")) or "://" in path:
        raise PromotionError("Unsafe evidence path")
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
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise PromotionError("Cannot read trusted GitHub evidence") from exc
    if not isinstance(payload, dict):
        raise PromotionError("Invalid GitHub evidence")
    return payload


def verified_receipt(sha: str, kind: str, token: str, read: Callable = github_read) -> bool:
    if kind not in RECEIPTS or not SHA.fullmatch(sha):
        raise PromotionError("Invalid receipt selector or SHA")
    workflow, prefix = RECEIPTS[kind]
    name = prefix + sha
    path = f"repos/{INFRA}/actions/artifacts?" + urllib.parse.urlencode(
        {"name": name, "per_page": 100}
    )
    payload = read(path, token)
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or payload.get("total_count", 0) > 100:
        raise PromotionError("Incomplete staging receipt evidence")
    for item in artifacts:
        if not isinstance(item, dict) or item.get("name") != name or item.get("expired") is not False:
            continue
        origin = item.get("workflow_run")
        if not isinstance(origin, dict) or origin.get("head_branch") != "main":
            continue
        run_id = origin.get("id")
        if type(run_id) is not int or run_id <= 0:
            continue
        run = read(f"repos/{INFRA}/actions/runs/{run_id}", token)
        if (
            run.get("id") == run_id
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("path") == workflow
            and run.get("head_branch") == "main"
            and (run.get("repository") or {}).get("full_name") == INFRA
            and run.get("event") in ({"workflow_dispatch"} if kind == "production-api" else {"workflow_dispatch", "push", "schedule"})
        ):
            return True
    return False


def admit(sha: str, token: str, *, read: Callable = github_read,
          source_ci: Callable = inspect_source_ci) -> None:
    if not SHA.fullmatch(sha) or not token:
        raise PromotionError("Explicit exact source SHA and read token required")
    compare = read(f"repos/{SOURCE}/compare/{sha}...main", token)
    if compare.get("status") not in {"ahead", "identical"}:
        raise PromotionError("Promotion source is not in protected main history")
    if source_ci(sha, token) != "ready":
        raise PromotionError("Exact source SHA did not pass all required CI")
    for kind in ("api", "pages"):
        if not verified_receipt(sha, kind, token, read):
            raise PromotionError(f"Missing successful exact-SHA staging {kind} receipt")
    print("CHRONICLES_PRODUCTION_STAGING_ADMITTED sha=" + sha)


def main() -> int:
    prod_api = len(sys.argv) == 3 and sys.argv[1] == "--production-api"
    if not (len(sys.argv) == 2 or prod_api):
        return 64
    try:
        token = os.environ.get("GH_TOKEN", "")
        if prod_api:
            sha = sys.argv[2]
            if not SHA.fullmatch(sha) or not token or not verified_receipt(sha, "production-api", token):
                raise PromotionError("Missing trusted production API receipt for exact SHA")
            print("CHRONICLES_PRODUCTION_API_ADMITTED sha=" + sha)
        else:
            admit(sys.argv[1], token)
    except (PromotionError, Exception) as exc:
        # Never emit raw network errors, URLs or credentials.
        if isinstance(exc, PromotionError):
            print("CHRONICLES_PRODUCTION_BLOCKED " + str(exc), file=sys.stderr)
        else:
            print("CHRONICLES_PRODUCTION_BLOCKED evidence unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
