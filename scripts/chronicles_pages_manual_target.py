#!/usr/bin/env python3
"""Reject ambiguous manual Pages target selections before any deployment jobs.

In particular, a hand-entered source_sha must never silently deploy staging
because the workflow_dispatch form defaults to staging.
"""
from __future__ import annotations

import os
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")


class TargetError(ValueError):
    pass


def validate_manual_target(event: str, target: str, source_sha: str,
                           only_if_new: str) -> None:
    if event != "workflow_dispatch":
        return
    if target not in {"staging", "production"} or only_if_new not in {"true", "false"}:
        raise TargetError("invalid manual Pages target or mode")
    if target == "staging":
        if source_sha and only_if_new == "false":
            raise TargetError(
                "source_sha was supplied but environment=staging; "
                "choose production explicitly for a production recovery")
        if only_if_new == "true" and not SHA.fullmatch(source_sha):
            raise TargetError("internal staging sync requires exact source_sha")
    else:
        if only_if_new == "true":
            raise TargetError("production cannot use internal staging sync mode")
        if not SHA.fullmatch(source_sha):
            raise TargetError("production needs an exact 40-hex source_sha")


def main() -> int:
    try:
        validate_manual_target(
            os.environ.get("GITHUB_EVENT_NAME", ""),
            os.environ.get("CHRONICLES_TARGET_ENV", ""),
            os.environ.get("CHRONICLES_SOURCE_SHA", ""),
            os.environ.get("CHRONICLES_ONLY_IF_NEW", "false"),
        )
    except TargetError as exc:
        # A fixed validation string only, never echo the supplied source.
        print("CHRONICLES_PAGES_MANUAL_TARGET_BLOCKED " + str(exc), file=sys.stderr)
        return 64
    print("CHRONICLES_PAGES_MANUAL_TARGET_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
