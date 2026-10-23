"""Guarded *staging-only* Pages rollback transaction; deliberately NO CLI entrypoint.

This module is not wired into GitHub Actions. A separately reviewed change must
supply a trusted main-branch freshness check and an explicit recovery workflow.
The checked-in authorization remains disabled. Do not import this from a publisher.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import UUID

import staradvs_pages as pages

ROOT = Path(__file__).resolve().parents[1]
AUTH_PATH = ROOT / "config" / "staradvs-recovery-authorization.json"
EXPIRY = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_AUTH_TTL = timedelta(hours=2)
REPO = "evilsysadmin/shadowops-infra"
ALLOWLIST_KEYS = {
    "mode", "operation", "live_sha", "target_sha", "target_deployment_id",
    "target_publish_run_id", "target_receipt_id", "hold_issue", "expires_at",
}


def load_authorization(path: Path = AUTH_PATH) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise pages.AdmissionError("Recovery authorization file missing; no rollback allowed") from None
    if len(text) > 4096:
        raise pages.AdmissionError("Recovery authorization is oversized")
    try:
        result = json.loads(text)
    except (ValueError, UnicodeError):
        raise pages.AdmissionError("Recovery authorization is invalid JSON") from None
    if not isinstance(result, dict):
        raise pages.AdmissionError("Recovery authorization must be an object")
    return result


def _expiry(value: object, now: datetime) -> None:
    if not isinstance(value, str) or not EXPIRY.fullmatch(value):
        raise pages.AdmissionError("Recovery approval expiry must be UTC")
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise pages.AdmissionError("Recovery clock is not UTC")
    try:
        deadline = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise pages.AdmissionError("Recovery approval has invalid UTC expiry") from None
    if deadline <= now or deadline - now > MAX_AUTH_TTL:
        raise pages.AdmissionError("Recovery approval expired or exceeds two hours")


def _uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def authorize_rollback(
    approval: object, hold: dict, plan: dict, confirmation: str,
    now: datetime, event: dict,
) -> dict:
    """Require a narrow, reviewed authorization matching exactly one historic release."""
    if not isinstance(approval, dict) or approval.get("mode") != "armed":
        raise pages.AdmissionError("Mutating staging recovery is disabled")
    if set(approval) != ALLOWLIST_KEYS or approval.get("operation") != "rollback":
        raise pages.AdmissionError("Recovery approval schema or operation is invalid")
    sha = approval.get("live_sha")
    target = approval.get("target_sha")
    if (not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha)
            or not isinstance(target, str) or not pages.SHA_PATTERN.fullmatch(target)
            or sha == target or not _uuid(approval.get("target_deployment_id"))
            or type(approval.get("target_publish_run_id")) is not int
            or approval["target_publish_run_id"] < 1
            or type(approval.get("target_receipt_id")) is not int
            or approval["target_receipt_id"] < 1):
        raise pages.AdmissionError("Recovery approval contains invalid source, target or receipt")
    _expiry(approval.get("expires_at"), now)
    if (not isinstance(hold, dict) or hold.get("mode") != "hold"
            or hold.get("anchor_sha") != sha
            or hold.get("issue") != approval.get("hold_issue")
            or not isinstance(hold.get("expires_at"), str)
            or plan.get("hold") != "active"
            or plan.get("hold_anchor_sha") != sha):
        raise pages.AdmissionError("Matching reviewed staging hold is not active")
    if (plan.get("live_sha") != sha or plan.get("forward_sha") != sha
            or plan.get("target_sha") != target
            or plan.get("target_deployment_id") != approval["target_deployment_id"]
            or plan.get("target_release_run_id") != approval["target_publish_run_id"]
            or plan.get("target_receipt_id") != approval["target_receipt_id"]
            or plan.get("can_mutate") is not False
            or plan.get("operator_approval") != "not_given"):
        raise pages.AdmissionError("Recovery approval differs from fresh read-only evidence")
    # A separate future operator workflow must supply its actual Actions context.
    if not isinstance(event, dict) or any((
        event.get("repository") != REPO,
        event.get("ref") != "refs/heads/main",
        event.get("event_name") != "workflow_dispatch",
        event.get("environment") != "staging-recovery",
    )):
        raise pages.AdmissionError("Rollback requires dedicated manual Infra main environment")
    expected = f"ROLLBACK {sha} TO {target}"
    if confirmation != expected:
        raise pages.AdmissionError("Explicit operator confirmation does not match exact SHAs")
    return {"live_sha": sha, "target_sha": target,
            "target_deployment_id": approval["target_deployment_id"]}


def rollback_once(
    client, reader, hold: dict, approval: dict, confirmation: str, now: datetime,
    event: dict, *,
    plan_builder: Callable,
    check_main: Callable,
    public_sha: Callable,
    public_integrity: Callable,
    recheck_hold: Callable,
) -> dict:
    """Guarded one-shot rollback capability, NOT connected to any workflow.

    All callbacks are required; production wiring must verify Infra main SHA,
    read the reviewed hold afresh, and refuse to mutate on any stale state.
    """
    if not all(callable(x) for x in (
        plan_builder, check_main, public_sha, public_integrity, recheck_hold,
    )):
        raise pages.AdmissionError("Rollback safety callbacks unavailable")
    if not isinstance(approval, dict) or approval.get("mode") != "armed":
        raise pages.AdmissionError("Recovery authorization disabled")
    # The builder MUST be the real GET-only recovery preflight (including
    # Cloudflare owner, GitHub receipt and immutable historic JS proof).
    plan = plan_builder(client, reader, hold, approval.get("target_sha", ""))
    selection = authorize_rollback(approval, hold, plan, confirmation, now, event)
    check_main()
    newest_hold = recheck_hold()
    if newest_hold != hold:
        raise pages.AdmissionError("Reviewed recovery hold changed before mutation")
    if public_sha() != selection["live_sha"]:
        raise pages.AdmissionError("Public release changed before rollback POST")
    check_main()
    deployment_id = selection["target_deployment_id"]
    path = (f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"
            f"/deployments/{deployment_id}/rollback")
    # Only single allowed Cloudflare mutation. This line MUST NOT be reachable
    # without a future separately reviewed, manually-approved workflow.
    code, outcome = client.request("POST", path)
    if (code not in (200, 201) or not isinstance(outcome, dict)
            or outcome.get("project_name") != pages.PROJECT
            or outcome.get("environment") != "production"):
        raise pages.AdmissionError("Pages rollback response did not confirm isolated staging")
    # Do not claim the restored game works until real public TLS/JS validation.
    public_integrity(selection["target_sha"])
    return {
        "status": "historic_staging_https_verified_browser_pending",
        "source_sha": selection["live_sha"],
        "restored_sha": selection["target_sha"],
        "deployment_id": deployment_id,
        "needs_public_browser_verification": True,
        "needs_explicit_forward_recovery": True,
    }
