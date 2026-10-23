#!/usr/bin/env python3
"""Read-only rehearsal plan for the dedicated Star Adventures staging Pages project.

No Cloudflare POST, no workflow dispatch, no deployment writes, no rollback.
An "armed" plan is evidence, not authorization to mutate.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import staradvs_pages as pages
from staradvs_staging_hold import HoldConfigError, load_hold
from staradvs_rollback_inventory import inventory, public_sha, valid_deployment
from staradvs_rollback_evidence import GitHubEvidence, corroborate
from staradvs_immutable_target import verify_immutable_target
from staradvs_forward_baseline import canonical_forward, forward_release_receipt


def select_attested_candidate(report: dict, requested_sha: str) -> dict:
    live_sha = report.get("live_sha")
    choices = report.get("receipt_backed_previous")
    if not isinstance(live_sha, str) or not pages.SHA_PATTERN.fullmatch(live_sha):
        raise pages.AdmissionError("Public live staging SHA is invalid")
    if requested_sha and not pages.SHA_PATTERN.fullmatch(requested_sha):
        raise pages.AdmissionError("Requested rollback SHA must be an exact lowercase 40-hex commit")
    if not isinstance(choices, list) or not choices:
        raise pages.AdmissionError("No receipt-backed previous staging releases to rehearse")
    valid = []
    for item in choices:
        if not isinstance(item, dict):
            raise pages.AdmissionError("Malformed receipt-backed candidate")
        sha = item.get("source_sha")
        release_id = item.get("deployment_id")
        run_id = item.get("infra_publish_run_id")
        receipt_id = item.get("verified_receipt_id")
        if (not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha)
                or sha == live_sha
                or not isinstance(release_id, str)
                or valid_deployment_identity(release_id) is False
                or type(run_id) is not int or run_id < 1
                or type(receipt_id) is not int or receipt_id < 1):
            raise pages.AdmissionError("Malformed receipt-backed candidate")
        valid.append(item)
    valid.sort(key=lambda item: item.get("created_on", ""), reverse=True)
    matches = [item for item in valid if item["source_sha"] == requested_sha] if requested_sha else valid[:1]
    if len(matches) != 1:
        raise pages.AdmissionError("Requested rollback SHA not uniquely receipt-backed in current Pages inventory")
    return matches[0]


def valid_deployment_identity(value: str) -> bool:
    from uuid import UUID
    try:
        return str(UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def confirm_exact_pages_candidate(client, candidate: dict) -> str:
    # Allowlisted by construction: fixed staging project + strictly typed UUID.
    deployment_id = candidate["deployment_id"]
    if not valid_deployment_identity(deployment_id):
        raise pages.AdmissionError("Unsafe Pages deployment identifier")
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments/{deployment_id}"
    code, row = client.request("GET", path)
    if code != 200:
        raise pages.AdmissionError("Pages deployment details missing")
    actual = valid_deployment(row)
    if (actual is None
            or actual["deployment_id"] != deployment_id
            or actual["source_sha"] != candidate["source_sha"]):
        raise pages.AdmissionError("Pages deployment details disagree with receipt-backed inventory")
    return verify_immutable_target(row, candidate["source_sha"])


def assess_hold(hold: dict, live_sha: str) -> dict:
    if hold["mode"] == "auto":
        return {"hold": "inactive", "rehearsal": "preview_only", "can_mutate": False}
    if hold["mode"] != "hold":
        raise pages.AdmissionError("Unknown hold mode")
    if hold["anchor_sha"] != live_sha:
        raise pages.AdmissionError("Hold anchor differs from publicly verified pre-rollback staging")
    return {
        "hold": "active",
        "rehearsal": "held_preflight_only",
        "can_mutate": False,
        "hold_anchor_sha": hold["anchor_sha"],
        "hold_expires_at": hold["expires_at"],
        "hold_issue": hold["issue"],
    }


def prepare_readonly_plan(client, evidence, hold: dict, requested_sha: str = "") -> dict:
    before = public_sha()
    forward = canonical_forward(client, before)
    forward_receipt = forward_release_receipt(evidence, before)
    report = inventory(client, before)
    attested = corroborate(report, evidence)
    chosen = select_attested_candidate(attested, requested_sha)
    immutable_url = confirm_exact_pages_candidate(client, chosen)
    hold_state = assess_hold(hold, before)
    after = public_sha()
    if after != before:
        raise pages.AdmissionError("Public staging changed during read-only rehearsal; retry after deployments settle")
    return {
        "project": pages.PROJECT,
        "public_url": pages.BASE,
        "live_sha": before,
        "target_sha": chosen["source_sha"],
        "target_deployment_id": chosen["deployment_id"],
        "target_immutable_url": immutable_url,
        "target_release_run_id": chosen["infra_publish_run_id"],
        "target_receipt_id": chosen["verified_receipt_id"],
        "rollback_api_method": "POST (not called)",
        "rollback_endpoint": "/accounts/{account_id}/pages/projects/" + pages.PROJECT
                             + "/deployments/" + chosen["deployment_id"] + "/rollback",
        "forward_sha": before,
        **forward,
        **forward_receipt,
        "forward_release_revalidation": "required (HTTPS JS SHA-256 + real Chrome + explicit hold release)",
        "operator_approval": "not_given",
        **hold_state,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GET-only staging recovery preflight")
    parser.add_argument("--candidate-sha", default="", help="optional exact historic 40-character source SHA")
    args = parser.parse_args(argv)
    try:
        hold = load_hold()
        client = pages.CloudflareClient(os.environ)
        evidence = GitHubEvidence(os.environ.get("GH_TOKEN", ""))
        result = prepare_readonly_plan(client, evidence, hold, args.candidate_sha)
        print("STARADVS_RECOVERY_READONLY_PREFLIGHT " + json.dumps(result, sort_keys=True))
        return 0
    except (pages.AdmissionError, HoldConfigError) as exc:
        print("STARADVS_RECOVERY_PREFLIGHT_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
