#!/usr/bin/env python3
"""Read-only deduplication of Bridge Squad's private, SHA-pinned Infra handoff.

This is not a deployment or a trust decision about the game's source:
source_admission.py independently checks green CI and the game artifact.
Only a completed successful Infra-main run may suppress a repeat upload.
All paths are fixed, all metadata is checked, and no candidate is downloaded.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "Bridge Squad · source release admission (read-only)"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_PAGES = 8
MAX_RESPONSE = 2_000_000


class Refused(ValueError):
    pass


class GitHubReader:
    def __init__(self, token: str):
        if not token:
            raise Refused("GitHub token unavailable")
        self.token = token

    def get(self, path: str):
        prefix = "/repos/" + REPO + "/actions/"
        if not path.startswith(prefix) or ".." in path or "://" in path:
            raise Refused("untrusted GitHub API path")
        req = urllib.request.Request(
            "https://api.github.com" + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise Refused("GitHub artifact metadata unavailable")
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise Refused("GitHub artifact metadata oversized")
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise Refused("invalid GitHub artifact response")
                return payload
        except (urllib.error.URLError, UnicodeError, ValueError) as exc:
            raise Refused("GitHub artifact inventory unavailable") from None


def already_sealed(reader, game_sha: str, infra_sha: str) -> bool:
    if (not isinstance(game_sha, str) or not SHA.fullmatch(game_sha) or
            not isinstance(infra_sha, str) or not SHA.fullmatch(infra_sha)):
        raise Refused("canonical game and infra commits required")
    name = "bridgesquad-sealed-" + game_sha + "-" + infra_sha
    for page in range(1, MAX_PAGES + 1):
        data = reader.get(f"/repos/{REPO}/actions/artifacts?per_page=100&page={page}")
        records = data.get("artifacts")
        if not isinstance(records, list) or len(records) > 100:
            raise Refused("artifact inventory malformed")
        for artifact in records:
            if not isinstance(artifact, dict) or artifact.get("name") != name:
                continue
            if artifact.get("expired") is True:
                continue
            run = artifact.get("workflow_run")
            if (artifact.get("expired") is not False or
                    type(artifact.get("id")) is not int or artifact["id"] <= 0 or
                    type(artifact.get("size_in_bytes")) is not int or
                    not 1 <= artifact["size_in_bytes"] <= MAX_RESPONSE or
                    not isinstance(artifact.get("digest"), str) or
                    not DIGEST.fullmatch(artifact["digest"]) or
                    not isinstance(run, dict) or
                    type(run.get("id")) is not int or run["id"] <= 0 or
                    run.get("head_sha") != infra_sha or
                    run.get("head_branch") != "main"):
                raise Refused("existing candidate metadata inconsistent")
            provenance = reader.get(f"/repos/{REPO}/actions/runs/{run['id']}")
            if (provenance.get("id") != run["id"] or
                    provenance.get("head_sha") != infra_sha or
                    provenance.get("head_branch") != "main" or
                    provenance.get("name") != WORKFLOW or
                    provenance.get("event") not in {"push", "workflow_dispatch", "schedule"}):
                raise Refused("existing candidate is not from admitted Infra run")
            # A candidate from an in-progress or failed run cannot authorize
            # skipping the current verified handoff.
            if provenance.get("status") == "completed" and provenance.get("conclusion") == "success":
                return True
        if len(records) < 100:
            return False
    # Conservative: an old artifact outside the bounded recent inventory
    # cannot suppress a new candidate, but also cannot authorize deployment.
    return False


def main(args: list[str]) -> int:
    if len(args) != 3 or args[0] != "check":
        print("Usage: bridgesquad_sealed_candidate_dedupe.py check GAME_SHA INFRA_SHA", file=sys.stderr)
        return 2
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != REPO or
                os.environ.get("GITHUB_REF") != "refs/heads/main" or
                os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch", "schedule"} or
                os.environ.get("GITHUB_SHA") != args[2]):
            raise Refused("trusted Infra main invocation required")
        found = already_sealed(GitHubReader(os.environ.get("GH_TOKEN", "")), args[1], args[2])
    except Refused:
        print("BRIDGESQUAD_SEALED_DEDUPE_REFUSED", file=sys.stderr)
        return 1
    print("sealed_exists=" + ("true" if found else "false"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
