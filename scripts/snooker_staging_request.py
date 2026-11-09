#!/usr/bin/env python3
"""Fail-closed receipt for a single authorized Snooker staging activation push.

The request is additive-only and anchored to one preapproved Infra main SHA.
Never invoke a cloud API here; actual mutation still requires the existing
staging-protected manual activation workflow and its protected children.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "snooker-staging-request.yml"
REQUEST = "ops/snooker-staging/activate-2026-11-09.json"
BASE = "bbdee7e1b83ab7d2b4688fdc94fc3e59192a7e7e"
EXPECTED = {
    "schema": 1,
    "application": "snooker",
    "environment": "staging",
    "request": "first-activation",
    "issue": 527,
    "base_main_sha": BASE,
    "single_use": True,
}
ALLOWED_DIFF = {
    REQUEST,
    ".github/workflows/" + WORKFLOW,
    "scripts/snooker_staging_request.py",
    "tests/test_snooker_staging_request.py",
    "docs/snooker-staging.md",
}
SHA_LENGTH = 40


class RequestDenied(RuntimeError):
    pass


def verify(content, changes, parent, head, environ):
    if json.loads(content) != EXPECTED:
        raise RequestDenied("Unrecognized or modified first activation request")
    if not isinstance(changes, dict) or changes.get(REQUEST) != "A":
        raise RequestDenied("Activation request must be added exactly once")
    if set(changes).difference(ALLOWED_DIFF):
        raise RequestDenied("Unrelated files mixed into the activation push")
    if parent != BASE or not isinstance(head, str) or len(head) != SHA_LENGTH:
        raise RequestDenied("Activation commit not on expected protected Infra main")
    required = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": head,
        "GITHUB_WORKFLOW_REF": (
            REPO + "/.github/workflows/" + WORKFLOW + "@refs/heads/main"
        ),
    }
    if any(environ.get(k) != v for k, v in required.items()):
        raise RequestDenied("Untrusted one-time staging request context")


def git(*args):
    p = subprocess.run(["git", *args], text=True, capture_output=True,
                       check=False, timeout=15)
    if p.returncode:
        raise RequestDenied("Cannot verify protected activation commit")
    return p.stdout.strip()


def main():
    try:
        content = Path(REQUEST).read_text(encoding="utf-8")
        head = git("rev-parse", "HEAD")
        parents = git("show", "-s", "--format=%P", "HEAD").split()
        if len(parents) != 1:
            raise RequestDenied("Activation must be a single-parent protected main commit")
        rows = git("diff", "--name-status", parents[0], head).splitlines()
        changes = {}
        for row in rows:
            parts = row.split("\t")
            if len(parts) != 2 or parts[0] not in ("A", "M"):
                raise RequestDenied("Unexpected activation diff type")
            changes[parts[1]] = parts[0]
        verify(content, changes, parents[0], head, os.environ)
        print("SNOOKER_STAGING_ONE_TIME_REQUEST_ADMITTED head=" + head)
        return 0
    except (RequestDenied, OSError, ValueError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        print("SNOOKER_STAGING_REQUEST_BLOCKED " + type(exc).__name__,
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
