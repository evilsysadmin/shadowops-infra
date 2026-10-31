#!/usr/bin/env python3
"""Read-only, exact-SHA CKA source CI admission for ShadowOps staging.

Only fixed, trusted workflow identities on protected source main are accepted.
A pending/missing result is not a green result. No providers are mutated.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Mapping

SOURCE = "evilsysadmin/cka-exam-simulator"
SHA = re.compile(r"^[0-9a-f]{40}$")
# Immutable workflow IDs from the source repo (not user-supplied names).
REQUIRED = {
    400311458: ("CI", ".github/workflows/ci.yml"),
    400786032: ("Go scenario contract", ".github/workflows/go-core.yml"),
    402323418: ("CKA account staging", ".github/workflows/account-staging.yml"),
}


class AdmissionError(Exception):
    pass


class RejectGithubRedirects(urllib.request.HTTPRedirectHandler):
    """Never resend an admission token after an HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_runs(sha: str, token: str) -> Mapping:
    if not isinstance(sha, str) or not SHA.fullmatch(sha) or not token:
        raise AdmissionError("Invalid source SHA or missing read token")
    params = urllib.parse.urlencode({"head_sha": sha, "event": "push", "per_page": 100})
    req = urllib.request.Request(
        "https://api.github.com/repos/" + SOURCE + "/actions/runs?" + params,
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    try:
        # urllib follows 301/302/307/308 by default. This is an authenticated
        # admission read: neither a foreign origin nor an unrelated GitHub
        # endpoint may receive the Authorization header or supply CI evidence.
        with urllib.request.build_opener(RejectGithubRedirects()).open(
                req, timeout=20) as response:
            if response.status != 200 or response.geturl() != req.full_url:
                raise AdmissionError("Unexpected source CI response URL or status")
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        raise AdmissionError("Source CI query HTTP " + str(exc.code)) from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise AdmissionError("Source CI query unavailable") from None
    if not isinstance(data, dict):
        raise AdmissionError("Invalid source CI response")
    return data


def inspect(sha: str, token: str, read: Callable = github_runs) -> str:
    """Return ready, pending or blocked. Only ready permits staging mutation."""
    if not SHA.fullmatch(sha) or not token:
        raise AdmissionError("Invalid source SHA or missing read token")
    payload = read(sha, token)
    if not isinstance(payload, Mapping):
        raise AdmissionError("Invalid source CI payload")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) > 100 or payload.get("total_count", 0) > 100:
        raise AdmissionError("Source CI result set is missing or incomplete")
    found = {}
    for run in runs:
        if not isinstance(run, dict):
            raise AdmissionError("Malformed source workflow run")
        identity = run.get("workflow_id")
        expected = REQUIRED.get(identity)
        if not expected:
            continue
        if (run.get("head_sha") != sha or run.get("event") != "push"
                or run.get("head_branch") != "main"
                or run.get("repository", {}).get("full_name") != SOURCE
                or run.get("path") != expected[1]
                or run.get("name") != expected[0]):
            # A result bearing a known workflow ID with mismatched provenance
            # must never be counted as a successful source check.
            raise AdmissionError("Untrusted source workflow identity")
        previous = found.get(identity)
        if previous is None or int(run.get("id", 0)) > int(previous.get("id", 0)):
            found[identity] = run
    if len(found) != len(REQUIRED):
        return "pending"
    if any(run.get("status") != "completed" for run in found.values()):
        return "pending"
    if any(run.get("conclusion") != "success" for run in found.values()):
        return "blocked"
    return "ready"


def main() -> int:
    if len(sys.argv) != 2:
        print("SOURCE_CI_BLOCKED bad-arguments", file=sys.stderr)
        return 64
    try:
        verdict = inspect(sys.argv[1], os.environ.get("GH_TOKEN", ""))
        # Exactly one word on stdout; safe to use as a shell gate.
        print(verdict)
        print("CHRONICLES_SOURCE_CI_" + verdict.upper() + " sha=" + sys.argv[1], file=sys.stderr)
        return 0
    except AdmissionError as exc:
        print("SOURCE_CI_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
