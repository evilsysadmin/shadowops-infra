#!/usr/bin/env python3
"""One-use Snooker staging resume after live read-only Identity container health.

This file never deploys anything. The staging-protected workflow must confirm
the host-installed root-owned Identity code and live container health BEFORE dispatching the
already existing independently-protected Snooker activation workflow.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "snooker-staging-resume.yml"
REQUEST = "ops/snooker-staging/resume-after-verified-identity-2026-11-10.json"
BASE = "5add17a61c7471f25b05267e1d601458b313a863"
INTENT = {
    "schema": 1,
    "application": "snooker",
    "environment": "staging",
    "request": "resume-after-verified-identity-health",
    "issue": 527,
    "base_main_sha": BASE,
    "single_use": True,
    "requires": "IDENTITY_WRAPPER_FINGERPRINT_CURRENT",
    "health": "identity-mongo=running/healthy identity=running/healthy identity-tunnel=running",
}
ALLOWED_FILES = frozenset({
    REQUEST,
    ".github/workflows/" + WORKFLOW,
    "scripts/snooker_staging_resume_request.py",
    "tests/test_snooker_staging_resume_request.py",
    "docs/snooker-staging.md",
})
SHA = re.compile(r"[0-9a-f]{40}\Z")


class RequestBlocked(ValueError):
    pass


def verify(text, changes, parents, head, env):
    try:
        if json.loads(text) != INTENT:
            raise RequestBlocked("Unexpected request content")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RequestBlocked("Invalid request JSON") from None
    if not isinstance(changes, dict) or changes.get(REQUEST) != "A":
        raise RequestBlocked("Only a first addition can resume Snooker")
    if set(changes) - ALLOWED_FILES or any(status not in {"A", "M"} for status in changes.values()):
        raise RequestBlocked("Unrelated or unsafe changes in resume commit")
    if parents != [BASE] or not isinstance(head, str) or not SHA.fullmatch(head):
        raise RequestBlocked("Resume request must be merged on the expected current main")
    trusted = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": head,
        "GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/" + WORKFLOW + "@refs/heads/main",
    }
    if any(env.get(key) != value for key, value in trusted.items()):
        raise RequestBlocked("Untrusted staging resume workflow context")


def git(*args):
    result = subprocess.run(["git", *args], check=False, capture_output=True,
                            text=True, timeout=15)
    if result.returncode != 0:
        raise RequestBlocked("Cannot verify trusted squash commit")
    return result.stdout.strip()


def main():
    try:
        head = git("rev-parse", "HEAD")
        parents = git("show", "-s", "--format=%P", "HEAD").split()
        if len(parents) != 1:
            raise RequestBlocked("Expected single-parent protected commit")
        changes = {}
        for row in git("diff", "--name-status", parents[0], head).splitlines():
            fields = row.split("\t")
            if len(fields) != 2 or fields[1] in changes:
                raise RequestBlocked("Unexpected Git diff")
            changes[fields[1]] = fields[0]
        verify(Path(REQUEST).read_text(encoding="utf-8"),
               changes, parents, head, os.environ)
        print("SNOOKER_STAGING_RESUME_REQUEST_ADMITTED head=" + head)
        return 0
    except (RequestBlocked, OSError, ValueError, subprocess.TimeoutExpired):
        print("SNOOKER_STAGING_RESUME_REQUEST_BLOCKED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
