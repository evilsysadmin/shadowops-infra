#!/usr/bin/env python3
"""Read-only, fail-closed preflight for explicitly reviewed legacy account links.

IMPORTANT: input files may contain usernames. Keep them OFF GitHub,
Actions logs, build artifacts and any shared storage. No DB connections,
accounts, passwords, emails, writes or IDs are generated here.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
import uuid
from pathlib import Path

MAX_PLAN_BYTES = 4 * 1024 * 1024
SOURCES = frozenset({"chess-studio", "chronicles"})
REVIEW_RE = re.compile(r"https://github[.]com/evilsysadmin/shadowops-infra/issues/[1-9][0-9]*\Z")


class PlanError(RuntimeError):
    pass


def _check_fields(value, required, kind: str) -> None:
    if not isinstance(value, dict) or set(value) != required:
        raise PlanError(f"{kind} fields invalid (PII or secrets not allowed)")


def _username_key(name: object) -> str:
    if (not isinstance(name, str) or not 1 <= len(name) <= 80
            or name != name.strip() or not name.isprintable()):
        raise PlanError("Legacy account identifier is invalid")
    return unicodedata.normalize("NFKC", name).casefold()


def _subject(value: object) -> str:
    if not isinstance(value, str):
        raise PlanError("Target sub must be an immutable UUIDv4")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise PlanError("Target sub must be an immutable UUIDv4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise PlanError("Target sub must be a canonical UUIDv4")
    return value


def validate_plan(value: object, expected_environment: str) -> tuple[dict, frozenset[str]]:
    """Validate linkage assertions only. Does NOT prove account ownership."""
    if expected_environment not in ("staging", "production"):
        raise PlanError("Unknown required environment")
    _check_fields(value, {"schema_version", "environment", "entries"}, "Plan")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise PlanError("Unexpected plan schema version")
    if value["environment"] != expected_environment:
        raise PlanError("Plan targets the wrong environment")
    entries = value["entries"]
    if not isinstance(entries, list) or not 0 < len(entries) <= 10000:
        raise PlanError("Plan must contain 1..10000 accounts")
    observed_source_names: set[tuple[str, str]] = set()
    source_subjects: set[tuple[str, str]] = set()
    grouped: dict[str, list[tuple[str, str | None]]] = {}
    for entry in entries:
        _check_fields(entry, {"source", "username", "subject", "link_review_ref"}, "Account")
        source = entry["source"]
        if not isinstance(source, str) or source not in SOURCES:
            raise PlanError("Unsupported legacy product")
        name = _username_key(entry["username"])
        subject = _subject(entry["subject"])
        ticket = entry["link_review_ref"]
        if ticket is not None and (not isinstance(ticket, str) or REVIEW_RE.fullmatch(ticket) is None):
            raise PlanError("Malformed account-link review reference")
        if (source, name) in observed_source_names:
            raise PlanError("Conflicting legacy account names (including Unicode/case aliases)")
        if (source, subject) in source_subjects:
            raise PlanError("Two accounts in one product cannot share one target sub")
        observed_source_names.add((source, name))
        source_subjects.add((source, subject))
        grouped.setdefault(subject, []).append((source, ticket))

    linked = 0
    for rows in grouped.values():
        if len(rows) > 1:
            # Never link Chess and Chronicles merely because their usernames happen to match.
            # A non-null common ticket is a machine-checkable *reference*, not proof of ownership.
            refs = {ticket for _source, ticket in rows}
            if len(refs) != 1 or None in refs or len({source for source, _ticket in rows}) != len(rows):
                raise PlanError("Cross-product merge needs one explicit reviewed link reference")
            linked += 1
    return ({
        "environment": expected_environment,
        "accounts": len(entries),
        "subjects": len(grouped),
        "cross_product_links_requiring_manual_review": linked,
    }, frozenset(grouped))


def validate_isolated_plans(staging: object, production: object | None = None) -> dict:
    """Production checks require the staging plan to catch reused UUIDs."""
    summary_staging, staging_subjects = validate_plan(staging, "staging")
    if production is None:
        return {"staging": summary_staging, "production": "not-audited"}
    summary_prod, production_subjects = validate_plan(production, "production")
    if staging_subjects & production_subjects:
        raise PlanError("Cross-environment stable-sub overlap is forbidden")
    return {"staging": summary_staging, "production": summary_prod}


def _load_private(path: Path) -> object:
    try:
        with path.open("rb") as fp:
            raw = fp.read(MAX_PLAN_BYTES + 1)
    except OSError as exc:
        raise PlanError("Cannot read private plan input") from exc
    if len(raw) > MAX_PLAN_BYTES:
        raise PlanError("Private plan exceeds size limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError("Invalid private plan JSON") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Identity link preflight; never mutates DB")
    parser.add_argument("--staging", required=True, type=Path, help="PRIVATE staging plan file outside repository")
    parser.add_argument("--production", type=Path, help="Optional PRIVATE production plan (compared to staging)")
    args = parser.parse_args(argv)
    try:
        result = validate_isolated_plans(
            _load_private(args.staging),
            _load_private(args.production) if args.production else None,
        )
    except PlanError as exc:
        # Never print usernames, subjects, raw exceptions, paths, tokens or hashes.
        print("SHADOWOPS_IDENTITY_LINK_PREFLIGHT_FAILED: " + str(exc), file=sys.stderr)
        return 1
    print("SHADOWOPS_IDENTITY_LINK_PREFLIGHT_OK " + json.dumps(result, sort_keys=True))
    print("No data migrated. Link references still require manual ownership verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
