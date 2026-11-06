#!/usr/bin/env python3
"""Compare manually obtained, sanitized Chronicles R2 operator/Infra receipts.

This is an OFFLINE discrepancy detector, not evidence authentication, permission
to publish, or an ownership cutover. Never print raw logs, R2 object keys, custom
prefixes, API bodies or credentials.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

from chronicles_r2_edge_probe import HOST, IMMUTABLE_SHA256, IMMUTABLE_SIZE
from chronicles_r2_private_inventory import MAX_PAGES

MAX_INPUT_BYTES = 512_000
OPERATOR_INVENTORY = "CHRONICLES_R2_OPERATOR_INVENTORY "
OPERATOR_PROBE = "CHRONICLES_R2_OPERATOR_PROBE "
OPERATOR_EDGE = "CHRONICLES_R2_IMMUTABLE_EDGE "
INFRA_PRIVATE = "CHRONICLES_R2_INVENTORY "
INFRA_EDGE = "CHRONICLES_R2_EDGE_OK "

REQUIRED = {
    OPERATOR_INVENTORY: frozenset({"objects", "bytes", "prefix_counts", "needs_review", "public_readiness"}),
    OPERATOR_PROBE: frozenset({"domain", "asset", "cors", "cache"}),
    OPERATOR_EDGE: frozenset({"asset", "public_sha256", "public_bytes", "browser_cache"}),
    INFRA_PRIVATE: frozenset({
        "domain", "objects", "bytes", "pages", "needs_review",
        "sprites", "music", "models", "other", "publication",
    }),
    INFRA_EDGE: frozenset({"edge", "bytes", "immutable_sha256"}),
}
IGNORED_OPERATOR_FIELDS = {
    OPERATOR_PROBE: frozenset({"url", "cache_header"}),
    OPERATOR_EDGE: frozenset({"url"}),
}
CATEGORIES = ("sprites", "music", "models", "other")


class ParityError(ValueError):
    """Fixed diagnostic without user-supplied data."""


def _read(path: pathlib.Path) -> str:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ParityError("receipt exceeds bounded input size")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ParityError("unable to read UTF-8 receipt file") from None


def _fields(text: str, prefixes: tuple[str, ...]) -> dict[str, dict[str, str]]:
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ParityError("receipt exceeds bounded input size")
    records: dict[str, dict[str, str]] = {prefix: {} for prefix in prefixes}
    for line in text.splitlines():
        if "CHRONICLES_R2_" in line and "_BLOCKED" in line:
            raise ParityError("receipt contains a blocked probe")
        for prefix in prefixes:
            if not line.startswith(prefix):
                continue
            raw = line[len(prefix):]
            # Chess Studio emits "key value"; Infra emits "key=value".
            parts = raw.split(" ", 1) if prefix.startswith("CHRONICLES_R2_OPERATOR_") or prefix == OPERATOR_EDGE else raw.split("=", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise ParityError("malformed receipt field")
            key, value = parts
            if key in IGNORED_OPERATOR_FIELDS.get(prefix, frozenset()):
                break
            if key not in REQUIRED[prefix]:
                raise ParityError("unexpected receipt field")
            if key in records[prefix]:
                raise ParityError("duplicate receipt field")
            records[prefix][key] = value.strip()
            break
    for prefix in prefixes:
        if set(records[prefix]) != REQUIRED[prefix]:
            raise ParityError("incomplete receipt")
    return records


def _nonnegative(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,17}", value):
        raise ParityError("invalid nonnegative receipt count")
    return int(value)


def _legacy_categories(raw: str, expected_objects: int) -> dict[str, int]:
    counts = dict.fromkeys(CATEGORIES, 0)
    if raw == "none":
        if expected_objects != 0:
            raise ParityError("legacy prefix breakdown missing objects")
        return counts
    labels = set()
    for item in raw.split(","):
        if item.count(":") != 1:
            raise ParityError("malformed legacy prefix breakdown")
        name, value = item.split(":", 1)
        # Unknown (possibly private) prefix names must never enter diagnostics.
        if not name or name in labels:
            raise ParityError("duplicate or empty legacy prefix")
        labels.add(name)
        count = _nonnegative(value)
        category = name if name in CATEGORIES[:-1] else "other"
        counts[category] += count
    if sum(counts.values()) != expected_objects:
        raise ParityError("legacy prefix breakdown does not match object count")
    return counts


def verify(operator_text: str, private_text: str, edge_text: str) -> dict[str, str]:
    operator = _fields(operator_text, (OPERATOR_INVENTORY, OPERATOR_PROBE, OPERATOR_EDGE))
    private = _fields(private_text, (INFRA_PRIVATE,))[INFRA_PRIVATE]
    edge = _fields(edge_text, (INFRA_EDGE,))[INFRA_EDGE]
    legacy = operator[OPERATOR_INVENTORY]
    old_probe = operator[OPERATOR_PROBE]
    old_edge = operator[OPERATOR_EDGE]

    if (old_probe["domain"] != HOST or old_probe["asset"] != "ok" or
        old_probe["cors"] != "ok" or old_probe["cache"] != "mutable-safe" or
        legacy["public_readiness"] != "manual-review-required"):
        raise ParityError("legacy probe did not meet its public contract")
    if (old_edge["asset"] != "ok" or old_edge["browser_cache"] != "immutable-one-year" or
        old_edge["public_sha256"] != IMMUTABLE_SHA256 or
        _nonnegative(old_edge["public_bytes"]) != IMMUTABLE_SIZE):
        raise ParityError("legacy immutable public receipt failed pinned contract")
    if private["domain"] != "approved-active" or private["publication"] != "not-authorized":
        raise ParityError("Infra private receipt did not meet read-only domain contract")
    if edge["edge"] != "ok" or edge["immutable_sha256"] != IMMUTABLE_SHA256 or (
        _nonnegative(edge["bytes"]) != IMMUTABLE_SIZE
    ):
        raise ParityError("Infra edge receipt failed pinned contract")

    left = {key: _nonnegative(legacy[key]) for key in ("objects", "bytes", "needs_review")}
    right = {key: _nonnegative(private[key]) for key in ("objects", "bytes", "needs_review")}
    for field in left:
        if left[field] != right[field]:
            raise ParityError("private inventory differs: " + field)
    if not 1 <= _nonnegative(private["pages"]) <= MAX_PAGES:
        raise ParityError("Infra private inventory page count invalid")

    legacy_counts = _legacy_categories(legacy["prefix_counts"], left["objects"])
    private_counts = {key: _nonnegative(private[key]) for key in CATEGORIES}
    if sum(private_counts.values()) != right["objects"]:
        raise ParityError("Infra family counts do not match object count")
    for category in CATEGORIES:
        if legacy_counts[category] != private_counts[category]:
            raise ParityError("R2 family count differs: " + category)
    return {
        "status": "matching-manual-receipts",
        "objects": str(left["objects"]),
        "bytes": str(left["bytes"]),
        "needs_review": str(left["needs_review"]),
        "sha256": IMMUTABLE_SHA256,
        "cutover": "not-authorized",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare manual R2 receipts offline (not a cutover)")
    parser.add_argument("--operator", type=pathlib.Path, required=True)
    parser.add_argument("--private", type=pathlib.Path, required=True)
    parser.add_argument("--edge", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(_read(args.operator), _read(args.private), _read(args.edge))
    except ParityError as exc:
        print("CHRONICLES_R2_HANDOFF_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    print("CHRONICLES_R2_HANDOFF_PARITY " + " ".join(
        f"{key}={value}" for key, value in sorted(report.items())
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
