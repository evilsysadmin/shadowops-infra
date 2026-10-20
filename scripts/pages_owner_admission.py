#!/usr/bin/env python3
"""Require sole ShadowOps ownership before publishing Chronicles staging Pages.

All calls are GET-only GitHub API reads. Refuses stale source revision,
unprotected main in either repository, or the old Chronicles-owned publisher.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Callable, Mapping

SOURCE = "evilsysadmin/chronicles-of-matthias"
OWNER = "evilsysadmin/shadowops-infra"
OLD_PUBLISHER = ".github/workflows/pages-staging.yml"
SOURCE_FRONTEND_CI = ".github/workflows/react-frontend.yml"
SHA = re.compile(r"^[0-9a-f]{40}$")


class AdmissionError(Exception):
    pass


def github_read(path: str, token: str) -> tuple[int, dict]:
    # GitHub's compare route uses SHA...main. Reject path traversal as an
    # entire segment, not a substring of a valid three-dot comparison.
    route = path.partition("?")[0]
    if (
        not route.startswith("/repos/")
        or "://" in path
        or "%" in route
        or "\\" in route
        or any(segment in {"", ".", ".."} for segment in route.split("/")[1:])
    ):
        raise AdmissionError("Unsafe GitHub API path")
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    if status not in (200, 404):
        raise AdmissionError("GitHub read failed (HTTP " + str(status) + ")")
    try:
        data = json.loads(body)
    except (UnicodeError, ValueError):
        raise AdmissionError("Invalid GitHub API payload") from None
    if not isinstance(data, dict):
        raise AdmissionError("Unexpected GitHub API response")
    return status, data


def admit(
    env: Mapping[str, str],
    read: Callable[[str, str], tuple[int, dict]] = github_read,
) -> str:
    if env.get("GITHUB_REPOSITORY") != OWNER or env.get("GITHUB_REF") != "refs/heads/main":
        raise AdmissionError("Only ShadowOps main may own this deployment")
    if env.get("GITHUB_EVENT_NAME") not in {"workflow_dispatch", "push", "schedule"}:
        raise AdmissionError("Owner handoff requires protected main dispatch or push")
    owner_sha = env.get("GITHUB_SHA", "").strip()
    source_sha = env.get("CHRONICLES_SOURCE_SHA", "").strip()
    token = env.get("GH_TOKEN", "")
    if not SHA.fullmatch(owner_sha) or not SHA.fullmatch(source_sha) or not token:
        raise AdmissionError("Missing source or owner SHA / read token")
    # Promotion (production) may ship an earlier commit of protected main —
    # the one validated on staging — but never a branch or unmerged commit.
    promote = env.get("CHRONICLES_RELEASE_MODE", "") == "promote"
    for repo, expected in ((OWNER, owner_sha), (SOURCE, source_sha)):
        status, branch = read(f"/repos/{repo}/branches/main", token)
        if status != 200:
            raise AdmissionError("Cannot establish protected main in " + repo)
        if branch.get("protected") is not True:
            raise AdmissionError("Main branch protection is inactive in " + repo)
        actual = (branch.get("commit") or {}).get("sha")
        if actual == expected:
            continue
        if promote and repo == SOURCE:
            status, compare = read(f"/repos/{SOURCE}/compare/{expected}...main", token)
            if status == 200 and compare.get("status") in {"ahead", "identical"}:
                continue
            raise AdmissionError("Promoted source is not on protected main")
        raise AdmissionError("Main has advanced; refusing stale " + repo + " release")

    # Strong handoff gate: an old manual publisher must not be runnable from
    # Chronicles main while ShadowOps can also write the same Pages domain.
    path = f"/repos/{SOURCE}/contents/{OLD_PUBLISHER}?ref=main"
    status, _ = read(path, token)
    if status != 404:
        raise AdmissionError("Legacy Chronicles Pages publisher still present")
    # Also reject the newer in-repository deploy job. Keeping frontend CI is
    # correct; giving it Cloudflare publish authority creates two CD owners.
    status, workflow = read(f"/repos/{SOURCE}/contents/{SOURCE_FRONTEND_CI}?ref=main", token)
    if status != 200 or workflow.get("encoding") != "base64":
        raise AdmissionError("Cannot inspect Chronicles frontend workflow ownership")
    try:
        source = base64.b64decode(workflow["content"], validate=False).decode("utf-8")
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AdmissionError("Invalid Chronicles frontend workflow content") from exc
    if any(needle in source for needle in (
        "deploy-staging:", "cloudflare/wrangler-action", "pages deploy ",
    )):
        raise AdmissionError("Chronicles frontend still has a Pages publisher")
    print("SHADOWOPS_CHRONICLES_PAGES_OWNER_ADMITTED source_sha=" + source_sha)
    return source_sha


def main() -> int:
    try:
        admit(os.environ)
    except AdmissionError as exc:
        print("SHADOWOPS_CHRONICLES_PAGES_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
