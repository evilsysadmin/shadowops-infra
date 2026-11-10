#!/usr/bin/env python3
"""Exactly one protected-main Atlas Identity release request for Snooker staging.

This script only validates the request. Only the separately protected GitHub
environment may dispatch the signed Atlas-only release workflow.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "snooker-atlas-release-retry-once.yml"
REQUEST = "ops/snooker-staging/atlas-release-retry-once-2026-11-10.json"
BASE = "b65ea5f0ecf9c67db0aa0b819ab1be5dba628f49"
IMAGE_SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
INTENT = {
  "schema": 1,
  "application": "snooker",
  "environment": "staging",
  "action": "atlas-release",
  "issue": 527,
  "source_sha": "4a48dff49c4a77703c6f4b164120d3cef8e77e76",
  "published_image_run": 42611388936,
  "successful_admin_run": 42807029176,
  "successful_restore_run": 42810596084,
  "successful_audit_run": 42821843479,
  "attempt": 2,
  "validated_digest": "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91",
  "base_main_sha": "b65ea5f0ecf9c67db0aa0b819ab1be5dba628f49",
  "single_use": True
}
FILES = frozenset({REQUEST, ".github/workflows/" + WORKFLOW,
                   "scripts/snooker_atlas_release_retry_request.py", "tests/test_snooker_atlas_release_retry_request.py"})
SHA = re.compile(r"[a-f0-9]{40}\Z")


class RequestBlocked(ValueError):
    pass


def verify(raw, changes, parents, head, env):
    if not isinstance(raw, str) or raw != json.dumps(INTENT, indent=2) + "\n":
        raise RequestBlocked("Unexpected immutable Atlas release request")
    if not isinstance(changes, dict) or changes != {path: "A" for path in FILES}:
        raise RequestBlocked("Atlas release request must be first-addition-only")
    if parents != [BASE] or not isinstance(head, str) or not SHA.fullmatch(head):
        raise RequestBlocked("Atlas release request must be merged on pinned main")
    context = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": head,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/" + WORKFLOW + "@refs/heads/main",
    }
    if any(env.get(key) != val for key, val in context.items()):
        raise RequestBlocked("Untrusted release dispatch context")


def git(*args):
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, timeout=15)
        if p.returncode:
            raise RequestBlocked("Cannot verify protected-main merge")
        return p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        raise RequestBlocked("Cannot verify protected-main merge") from None


def main():
    try:
        head = git("rev-parse", "HEAD")
        parents = git("show", "-s", "--format=%P", "HEAD").split()
        if len(parents) != 1:
            raise RequestBlocked("Not a single-parent protected main commit")
        changes = {}
        for row in git("diff", "--name-status", parents[0], head).splitlines():
            parts = row.split("\t")
            if len(parts) != 2 or parts[1] in changes:
                raise RequestBlocked("Invalid release commit diff")
            changes[parts[1]] = parts[0]
        verify(Path(REQUEST).read_text(encoding="utf-8"),
               changes, parents, head, os.environ)
        print("SNOOKER_ATLAS_RELEASE_REQUEST_ACCEPTED source_sha=" + IMAGE_SHA)
        return 0
    except (RequestBlocked, OSError, ValueError, TypeError):
        print("SNOOKER_ATLAS_RELEASE_REQUEST_BLOCKED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
