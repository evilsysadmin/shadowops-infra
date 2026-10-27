#!/usr/bin/env python3
"""Verify a human-selected Star Adventures recovery plan, never authorize mutation.

Reads only a verified GET-only staging preflight log. No network or Cloudflare API
client, no POST, and no import of rollback/forward transaction modules.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import staradvs_pages as pages
from staradvs_recovery_preflight import valid_deployment_identity
from staradvs_immutable_target import immutable_origin

PREFIX = "STARADVS_RECOVERY_READONLY_PREFLIGHT "
MAX_BYTES = 65536


def validate_operator_plan(
    log: str, expected_live_sha: str, target_sha: str, confirmation: str,
) -> dict:
    if (not isinstance(expected_live_sha, str)
            or not pages.SHA_PATTERN.fullmatch(expected_live_sha)
            or not isinstance(target_sha, str)
            or not pages.SHA_PATTERN.fullmatch(target_sha)
            or expected_live_sha == target_sha):
        raise pages.AdmissionError("Exact and distinct 40-hex staging SHAs required")
    if confirmation != f"PLAN {expected_live_sha} TO {target_sha}":
        raise pages.AdmissionError("Operator read-only PLAN confirmation mismatched")
    entries = [line[len(PREFIX):] for line in log.splitlines() if line.startswith(PREFIX)]
    if len(entries) != 1:
        raise pages.AdmissionError("Expected exactly one independently verified recovery report")
    try:
        data = json.loads(entries[0])
    except (ValueError, UnicodeError):
        raise pages.AdmissionError("Operator recovery report is invalid JSON") from None
    if not isinstance(data, dict):
        raise pages.AdmissionError("Operator recovery report must be an object")
    if (data.get("project") != pages.PROJECT or data.get("public_url") != pages.BASE
            or data.get("live_sha") != expected_live_sha
            or data.get("forward_sha") != expected_live_sha
            or data.get("target_sha") != target_sha
            or data.get("rollback_api_method") != "POST (not called)"
            or data.get("can_mutate") is not False
            or data.get("operator_approval") != "not_given"):
        raise pages.AdmissionError("Operator report identities or read-only status mismatched")
    state = data.get("hold")
    if state == "inactive":
        if data.get("rehearsal") != "preview_only":
            raise pages.AdmissionError("Operator report inactive hold has invalid state")
    elif state == "active":
        if (data.get("rehearsal") != "held_preflight_only"
                or data.get("hold_anchor_sha") != expected_live_sha):
            raise pages.AdmissionError("Operator report has wrong reviewed hold anchor")
    else:
        raise pages.AdmissionError("Operator report hold state unknown")
    for field in ("forward_deployment_id", "target_deployment_id"):
        if not valid_deployment_identity(data.get(field)):
            raise pages.AdmissionError("Operator recovery Pages deployment ID invalid")
    if data["forward_deployment_id"] == data["target_deployment_id"]:
        raise pages.AdmissionError("Forward and historical deployment IDs must differ")
    # Cloudflare's immutable Pages host begins with the deployment UUID's
    # eight-hex prefix. A valid staging-project URL is not sufficient: the
    # operator must not accept a URL belonging to another Pages deployment.
    for deployment_field, origin_field in (
        ("forward_deployment_id", "forward_immutable_url"),
        ("target_deployment_id", "target_immutable_url"),
    ):
        origin = immutable_origin(data.get(origin_field))
        origin_prefix = origin.removeprefix("https://").split(".", 1)[0][:8]
        deployment_prefix = data[deployment_field].split("-", 1)[0]
        if origin_prefix != deployment_prefix:
            raise pages.AdmissionError("Immutable Pages origin mismatches deployment UUID")
    for field in ("forward_publish_run_id", "forward_receipt_id",
                  "target_release_run_id", "target_receipt_id"):
        if type(data.get(field)) is not int or data[field] <= 0:
            raise pages.AdmissionError("Operator recovery receipt evidence is missing")
    return {
        "mode": "read_only_operator_plan",
        "live_sha": expected_live_sha,
        "target_sha": target_sha,
        "hold": state,
        "forward_deployment_id": data["forward_deployment_id"],
        "target_deployment_id": data["target_deployment_id"],
        "can_mutate": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a GET-only staging recovery plan")
    parser.add_argument("--log", required=True)
    parser.add_argument("--live-sha", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    try:
        source = Path(args.log)
        raw = source.read_bytes()
        if not raw or len(raw) > MAX_BYTES:
            raise pages.AdmissionError("Operator preflight output missing or oversized")
        result = validate_operator_plan(
            raw.decode("utf-8"), args.live_sha, args.target_sha, args.confirmation,
        )
        print("STARADVS_OPERATOR_RECOVERY_PLAN_ONLY " + json.dumps(result, sort_keys=True))
        return 0
    except (pages.AdmissionError, OSError, UnicodeError) as exc:
        print("STARADVS_OPERATOR_PLAN_BLOCKED " + str(exc), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
