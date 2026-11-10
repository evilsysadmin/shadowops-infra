#!/usr/bin/env python3
"""Exact, single-use protected-main request for Atlas-only Snooker restore.

Admission never performs remote work. The paired protected staging workflow
dispatches the existing isolated Atlas restore after a verified synthetic admin journey, not a live Identity deploy.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "snooker-atlas-restore-once.yml"
REQUEST = "ops/snooker-staging/atlas-restore-once-2026-11-10.json"
BASE = "324c7fd1630fc44dff53a1263b4d816e8f4190a5"
IMAGE_SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
INTENT = {
    "schema": 1, "application": "snooker", "environment": "staging",
    "action": "atlas-restore", "issue": 527,
    "source_sha": IMAGE_SHA, "published_image_run": 42611388936,
    "successful_admin_run": 42807029176,
    "validated_digest": "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91",
    "base_main_sha": BASE, "single_use": True,
}
FILES = frozenset({
    REQUEST,
    ".github/workflows/" + WORKFLOW,
    "scripts/snooker_atlas_restore_request.py",
    "tests/test_snooker_atlas_restore_request.py",
})
SHA = re.compile(r"[0-9a-f]{40}\Z")


class RequestBlocked(ValueError):
    pass


def verify(raw, changes, parents, head, env):
    if not isinstance(raw, str) or raw != json.dumps(INTENT, indent=2) + "\n":
        raise RequestBlocked("Unexpected or noncanonical Atlas request")
    if changes.get(REQUEST) != "A" or set(changes) - FILES:
        raise RequestBlocked("Atlas restore must be a first-addition-only request")
    if any(v not in ("A", "M") for v in changes.values()):
        raise RequestBlocked("Unexpected change type")
    if parents != [BASE] or not isinstance(head, str) or not SHA.fullmatch(head):
        raise RequestBlocked("Request must be merged on exact protected main")
    context = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": head,
        "GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/" + WORKFLOW + "@refs/heads/main",
    }
    if any(env.get(k) != v for k, v in context.items()):
        raise RequestBlocked("Untrusted push context")


def git(*args):
    p = subprocess.run(["git", *args], capture_output=True, text=True, timeout=15)
    if p.returncode:
        raise RequestBlocked("Cannot validate protected request merge")
    return p.stdout.strip()


def main():
    try:
        head = git("rev-parse", "HEAD")
        parents = git("show", "-s", "--format=%P", "HEAD").split()
        if len(parents) != 1:
            raise RequestBlocked("Expected one protected-main parent")
        changes = {}
        for line in git("diff", "--name-status", parents[0], head).splitlines():
            pair = line.split("\t")
            if len(pair) != 2 or pair[1] in changes:
                raise RequestBlocked("Invalid commit diff")
            changes[pair[1]] = pair[0]
        verify(Path(REQUEST).read_text(encoding="utf-8"),
               changes, parents, head, os.environ)
        print("SNOOKER_ATLAS_RESTORE_REQUEST_ACCEPTED source_sha=" + IMAGE_SHA)
        return 0
    except (RequestBlocked, OSError, ValueError, subprocess.TimeoutExpired):
        print("SNOOKER_ATLAS_RESTORE_REQUEST_BLOCKED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
