#!/usr/bin/env python3
"""Fail closed when staging-relevant Infra files changed after checkout.

Changes to unrelated teams (e.g. Chronicles, Football) must not invalidate an
already admitted Star Adventures build. Compare immutable *blob IDs*, never
just the moving Infra main commit, and reject incomplete GitHub tree evidence.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

REPO = "evilsysadmin/shadowops-infra"
SHA = re.compile(r"^[0-9a-f]{40}$")


class RevisionError(Exception):
    pass


def is_relevant(path: str) -> bool:
    return (
        path.startswith(".github/workflows/staradvs-")
        or path.startswith("scripts/staradvs_")
        or path.startswith("config/staradvs-")
        or path.startswith("tests/test_staradvs_")
        or path.startswith("tests/staradvs-")
    )


def relevant_blobs(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict) or payload.get("truncated") is not False:
        raise RevisionError("Infra tree evidence missing or truncated")
    entries = payload.get("tree")
    if not isinstance(entries, list):
        raise RevisionError("Infra tree entries missing")
    blobs = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RevisionError("Malformed Infra tree entry")
        path = entry["path"]
        if not is_relevant(path):
            continue
        oid = entry.get("sha")
        if entry.get("type") != "blob" or not isinstance(oid, str) or not SHA.fullmatch(oid):
            raise RevisionError("Malformed protected staging blob: " + path)
        if path in blobs:
            raise RevisionError("Duplicate protected staging path: " + path)
        blobs[path] = oid
    # The pipeline is not admissible if its own policy is missing at either
    # revision. This also guards against unexpected empty/unrelated API data.
    if ".github/workflows/staradvs-pages-staging.yml" not in blobs:
        raise RevisionError("Staging publisher policy not present in Infra tree")
    return blobs


def compare(pinned_sha: str, current_sha: str, read_tree) -> tuple[bool, list[str]]:
    if not SHA.fullmatch(pinned_sha) or not SHA.fullmatch(current_sha):
        raise RevisionError("Invalid immutable Infra revision")
    if pinned_sha == current_sha:
        return True, []
    before = relevant_blobs(read_tree(pinned_sha))
    after = relevant_blobs(read_tree(current_sha))
    changed = sorted(path for path in before.keys() | after.keys()
                     if before.get(path) != after.get(path))
    return not changed, changed


def github_tree(sha: str) -> dict:
    path = f"repos/{REPO}/git/trees/{sha}?recursive=1"
    try:
        result = subprocess.run(["gh", "api", path], check=True,
                                capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, ValueError) as exc:
        raise RevisionError("Cannot verify Infra tree: " + type(exc).__name__) from None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: staradvs_infra_revision.py <pinned-infra-sha> <current-infra-sha>",
              file=sys.stderr)
        return 64
    try:
        safe, changed = compare(argv[0], argv[1], github_tree)
        if not safe:
            raise RevisionError("Staging-owned Infra paths changed: " + ", ".join(changed))
        label = "SAME" if argv[0] == argv[1] else "UNRELATED_MAIN_ADVANCE_ALLOWED"
        print(f"STARADVS_INFRA_{label} pinned={argv[0]} current={argv[1]}")
        return 0
    except RevisionError as exc:
        print("STARADVS_INFRA_REVISION_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
