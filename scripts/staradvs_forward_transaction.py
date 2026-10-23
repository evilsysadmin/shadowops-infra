"""One-shot guarded roll-forward to a previously attested canonical Pages staging deploy.

Import-only module. NO CLI, workflow caller, configured recovery environment or
live POST permission is provided. All tests use simulated Cloudflare clients.
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable

import staradvs_pages as pages
from staradvs_rollback_inventory import valid_deployment
from staradvs_recovery_preflight import confirm_exact_pages_candidate
from staradvs_rollback_evidence import GitHubEvidence
from staradvs_forward_baseline import forward_release_receipt
from staradvs_staging_hold import HoldConfigError, parse_hold
from staradvs_immutable_target import immutable_origin
from staradvs_recovery_transaction import (
    ALLOWLIST_KEYS, REPO, _expiry, _uuid,
)


def authorize_forward(
    approval: object, hold: dict, original: dict, confirmation: str,
    now: datetime, event: dict,
) -> dict:
    """Only authorize original canonical deployment, never latest main by guess."""
    if not isinstance(approval, dict) or approval.get("mode") != "armed":
        raise pages.AdmissionError("Forward recovery approval disabled")
    if set(approval) != ALLOWLIST_KEYS or approval.get("operation") != "forward":
        raise pages.AdmissionError("Forward recovery requires a distinct reviewed operation")
    _expiry(approval.get("expires_at"), now)
    if not isinstance(original, dict):
        raise pages.AdmissionError("Original pre-rollback evidence missing")
    source_sha = original.get("target_sha")  # Historic rollback target now live.
    forward_sha = original.get("forward_sha")  # Original canonical deployment.
    if (not isinstance(source_sha, str) or not pages.SHA_PATTERN.fullmatch(source_sha)
            or not isinstance(forward_sha, str) or not pages.SHA_PATTERN.fullmatch(forward_sha)
            or forward_sha == source_sha):
        raise pages.AdmissionError("Original baseline source identities are invalid")
    if (not _uuid(original.get("target_deployment_id"))
            or not _uuid(original.get("forward_deployment_id"))
            or type(original.get("forward_publish_run_id")) is not int
            or original["forward_publish_run_id"] <= 0
            or type(original.get("forward_receipt_id")) is not int
            or original["forward_receipt_id"] <= 0):
        raise pages.AdmissionError("Original baseline lacks exact Pages and receipt identity")
    if (approval.get("live_sha") != source_sha
            or approval.get("target_sha") != forward_sha
            or approval.get("target_deployment_id") != original["forward_deployment_id"]
            or approval.get("target_publish_run_id") != original["forward_publish_run_id"]
            or approval.get("target_receipt_id") != original["forward_receipt_id"]):
        raise pages.AdmissionError("Forward approval differs from original canonical deployment")
    if (original.get("live_sha") != forward_sha
            or original.get("hold") != "active"
            or original.get("hold_anchor_sha") != forward_sha
            or original.get("can_mutate") is not False
            or original.get("operator_approval") != "not_given"):
        raise pages.AdmissionError("Pre-rollback evidence lacks a reviewed original baseline")
    immutable_origin(original.get("forward_immutable_url"))
    immutable_origin(original.get("target_immutable_url"))
    try:
        validated_hold = parse_hold(hold, now)
    except HoldConfigError:
        raise pages.AdmissionError("Forward recovery hold expired or invalid") from None
    if (validated_hold.get("mode") != "hold"
            or validated_hold.get("anchor_sha") != forward_sha
            or validated_hold.get("issue") != approval.get("hold_issue")):
        raise pages.AdmissionError("Original staging hold is no longer active")
    if not isinstance(event, dict) or any((
        event.get("repository") != REPO,
        event.get("ref") != "refs/heads/main",
        event.get("event_name") != "workflow_dispatch",
        event.get("environment") != "staging-recovery",
    )):
        raise pages.AdmissionError("Forward requires dedicated manual Infra main environment")
    if confirmation != f"FORWARD {source_sha} TO {forward_sha}":
        raise pages.AdmissionError("Forward operator confirmation does not match exact SHAs")
    return {
        "source_sha": source_sha,
        "forward_sha": forward_sha,
        "forward_deployment_id": original["forward_deployment_id"],
        "forward_publish_run_id": original["forward_publish_run_id"],
        "forward_receipt_id": original["forward_receipt_id"],
        "forward_immutable_url": original["forward_immutable_url"],
    }


def forward_once(
    client, reader: GitHubEvidence, hold: dict, approval: dict,
    original: dict, confirmation: str, now: datetime, event: dict, *,
    check_main: Callable, public_sha: Callable,
    public_integrity: Callable, recheck_hold: Callable,
    restored_browser_proof: Callable,
) -> dict:
    """Fail-closed staged forward transaction (not connected to Actions).

    The restored browser proof must independently verify a completed public
    browser journey for the historic source. No truthy stand-in is acceptable.
    """
    callbacks = (check_main, public_sha, public_integrity,
                 recheck_hold, restored_browser_proof)
    if not all(callable(callback) for callback in callbacks):
        raise pages.AdmissionError("Required forward safety callbacks missing")
    selection = authorize_forward(approval, hold, original, confirmation, now, event)
    check_main()
    if recheck_hold() != hold:
        raise pages.AdmissionError("Reviewed staging hold changed")
    if restored_browser_proof(selection["source_sha"]) is not True:
        raise pages.AdmissionError("Public Chrome/F5 proof for restored source absent")
    if public_sha() != selection["source_sha"]:
        raise pages.AdmissionError("Restored public source changed before forward")

    # Require Pages itself to attest that the currently canonical release IS
    # the historic rollback target; serving a stale cached manifest is not enough.
    code, project = client.request(
        "GET", f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"
    )
    if (code != 200 or not isinstance(project, dict)
            or project.get("name") != pages.PROJECT
            or project.get("production_branch") != "main"):
        raise pages.AdmissionError("Forward canonical project ownership failed")
    canonical = valid_deployment(project.get("canonical_deployment"))
    if (canonical is None
            or canonical["source_sha"] != selection["source_sha"]):
        raise pages.AdmissionError("Pages current canonical is not the restored release")

    # Directly re-probe the ORIGINAL deployment UUID + immutable JS bytes,
    # without relying on a historical snapshot alone.
    origin = confirm_exact_pages_candidate(client, {
        "deployment_id": selection["forward_deployment_id"],
        "source_sha": selection["forward_sha"],
    })
    if origin != selection["forward_immutable_url"]:
        raise pages.AdmissionError("Forward immutable URL no longer matches the baseline")
    receipt = forward_release_receipt(reader, selection["forward_sha"])
    if (receipt["forward_publish_run_id"] != selection["forward_publish_run_id"]
            or receipt["forward_receipt_id"] != selection["forward_receipt_id"]):
        raise pages.AdmissionError("Original forward release receipt changed or expired")

    check_main()
    if recheck_hold() != hold or public_sha() != selection["source_sha"]:
        raise pages.AdmissionError("Restored staging or hold moved before forward POST")
    path = (f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"
            f"/deployments/{selection['forward_deployment_id']}/rollback")
    status, result = client.request("POST", path)
    if (status not in (200, 201) or not isinstance(result, dict)
            or result.get("project_name") != pages.PROJECT
            or result.get("environment") != "production"):
        raise pages.AdmissionError("Forward response did not confirm isolated staging")
    public_integrity(selection["forward_sha"])
    return {
        "status": "original_staging_https_verified_browser_pending",
        "restored_from_sha": selection["source_sha"],
        "forward_sha": selection["forward_sha"],
        "forward_deployment_id": selection["forward_deployment_id"],
        "needs_forward_public_browser_verification": True,
        "needs_separately_reviewed_hold_resume": True,
    }
