#!/usr/bin/env python3
"""Independent read-only Snooker drift watchdog.

It has NO deploy/cloud-write code. A stale deployed SHA may request the
existing protected publisher, only after independent exact green-main CI
admission. The publisher rechecks everything before any cloud writes.
"""
from __future__ import annotations

import os
import re
import sys

import snooker_source_admission as admission
import snooker_staging_publish as publish
from snooker_pages_provision import Client

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = "snooker-staging-watchdog.yml"
ALLOWED_EVENTS = frozenset({"schedule", "workflow_dispatch", "push"})
SHA = re.compile(r"[a-f0-9]{40}\Z")


class WakeBlocked(RuntimeError):
    pass


def valid_context(env):
    return (
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY") == REPO
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_EVENT_NAME") in ALLOWED_EVENTS
        and env.get("GITHUB_WORKFLOW_REF") ==
            REPO + "/.github/workflows/" + WORKFLOW + "@refs/heads/main"
        and isinstance(env.get("GITHUB_SHA"), str)
        and SHA.fullmatch(env["GITHUB_SHA"]) is not None
        and isinstance(env.get("GITHUB_OUTPUT"), str)
        and bool(env["GITHUB_OUTPUT"])
    )


def decide(reader, client, *, plan=publish.plan_automatic_release,
           admit=admission.admit):
    source = admission.current_sha(reader)
    # Reads canonical Pages metadata, existing Identity callback and guest
    # denial. The existing source CI ZIP need not exist for a current no-op.
    decision = plan(client, source)
    if decision == {"publish": False, "reason": "current"}:
        return None
    if decision != {"publish": True, "reason": "source-mismatch"}:
        raise WakeBlocked("Unexpected release plan")
    # Red CI, PR artifacts, missing SHA256, expired ZIP or moved source:
    # DO NOT dispatch. This deliberately matches the protected publisher.
    proof = admit(reader, source)
    if not isinstance(proof, dict) or proof.get("source_sha") != source:
        raise WakeBlocked("Exact source admission mismatch")
    if admission.current_sha(reader) != source:
        raise WakeBlocked("Source main advanced during watchdog preflight")
    return source


def main(env=None):
    env = os.environ if env is None else env
    try:
        if not valid_context(env):
            raise WakeBlocked("Untrusted Actions context")
        reader = admission.GithubReader(env.get("GH_TOKEN", ""))
        source = decide(reader, Client(env))
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("dispatch=" + ("true" if source else "false") + "\n")
            if source:
                output.write("source_sha=" + source + "\n")
        print("SNOOKER_WATCHDOG status=" +
              ("admitted-drift" if source else "current") +
              " dispatch=" + ("true" if source else "false") +
              (" source=" + source[:12] if source else ""))
        return 0
    except Exception as exc:
        # No exceptions, HTTP bodies, tokens, vault data or URLs are logged.
        print("SNOOKER_WATCHDOG_BLOCKED type=" + type(exc).__name__,
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
