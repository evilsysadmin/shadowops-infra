#!/usr/bin/env python3
"""Operator-authorized Snooker staging activation via existing protected Actions.

No Cloudflare or OCI credentials are handled here. A human with an authorized
GitHub CLI session explicitly requests --apply; every remote workflow still
enforces its own protected staging environment and immutable source gates.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request

INFRA = "evilsysadmin/shadowops-infra"
GAME = "evilsysadmin/snooker-of-matthias"
IDENTITY_WORKFLOW = "identity-staging-operations.yml"
PAGES_WORKFLOW = "snooker-pages-release.yml"
IDENTITY_IMAGE_WORKFLOW = "identity-service.yml"
IMAGE_PUBLICATION_STEPS = {
    "Run docker/build-push-action@v7",
    "Run actions/attest-build-provenance@v4",
    "Record admitted image digest",
}
SNOOKER_CONTRACT_SHA = "5bd2388d47337619cff80ab06bbf21b9f4cd31cc"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RELEASE_URL = "https://id-staging.shadowops.dpdns.org/api/identity/release"


class ActivationBlocked(RuntimeError):
    pass


def gh(*args, timeout=60):
    try:
        result = subprocess.run(
            ["gh", *args], capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ActivationBlocked("GitHub CLI missing or timed out: " + type(exc).__name__) from None
    if result.returncode:
        # GitHub's stderr may include private details; don't echo it to CI/logs.
        raise ActivationBlocked("GitHub action failed: " + " ".join(args[:2]))
    return result.stdout.strip()


def api(path):
    try:
        value = json.loads(gh("api", path))
    except (ValueError, TypeError):
        raise ActivationBlocked("GitHub returned invalid JSON") from None
    if not isinstance(value, dict):
        raise ActivationBlocked("GitHub returned a non-object")
    return value


def main_sha(repo):
    value = api(f"repos/{repo}/commits/main").get("sha")
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ActivationBlocked("Cannot establish protected main for " + repo)
    return value


def no_downgrade(current, candidate):
    if not SHA.fullmatch(current) or not SHA.fullmatch(candidate):
        raise ActivationBlocked("Identity source SHA must be 40 lowercase hex")
    # Compare base...head: 'ahead' means the candidate contains the base,
    # 'behind' means an attempted rollback. Reject divergence as well.
    for base in (SNOOKER_CONTRACT_SHA, current):
        comparison = api(f"repos/{INFRA}/compare/{base}...{candidate}")
        if comparison.get("status") not in ("ahead", "identical"):
            raise ActivationBlocked("Identity candidate would omit Snooker or downgrade staging")


def latest_identity_image_sha():
    """Read-only discovery of last actually published protected Identity image.

    This is a candidate only: the protected deploy still verifies GHCR manifest,
    arm64 image, signed attestation and required checks before any installation.
    """
    result = api(
        f"repos/{INFRA}/actions/workflows/{IDENTITY_IMAGE_WORKFLOW}/runs?"
        "event=push&branch=main&per_page=50"
    )
    runs = result.get("workflow_runs")
    if not isinstance(runs, list):
        raise ActivationBlocked("Identity image run inventory unavailable")
    for run in runs:
        if not isinstance(run, dict):
            continue
        candidate = run.get("head_sha")
        if (
            not isinstance(candidate, str) or not SHA.fullmatch(candidate)
            or run.get("event") != "push"
            or run.get("head_branch") != "main"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
        ):
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            continue
        jobs = api(f"repos/{INFRA}/actions/runs/{run_id}/jobs?per_page=100").get("jobs")
        if not isinstance(jobs, list):
            raise ActivationBlocked("Identity image jobs unavailable")
        publish = [job for job in jobs if isinstance(job, dict)
                   and job.get("name") == "Publish SHA-pinned Identity staging image"]
        if len(publish) != 1 or publish[0].get("conclusion") != "success":
            continue
        passed = {step.get("name") for step in (publish[0].get("steps") or [])
                  if isinstance(step, dict) and step.get("status") == "completed"
                  and step.get("conclusion") == "success"}
        if not IMAGE_PUBLICATION_STEPS.issubset(passed):
            continue
        return candidate
    raise ActivationBlocked(
        "No published Identity image found; run identity-service.yml "
        "on protected main and retry",
    )


def deployed_identity_sha():
    try:
        request = urllib.request.Request(
            RELEASE_URL, headers={"User-Agent": "ShadowOps-Snooker-Operator/1.0"},
        )
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status != 200:
                raise ActivationBlocked("Cannot prove currently running Identity")
            raw = response.read(4097)
        if len(raw) > 4096:
            raise ActivationBlocked("Identity release receipt too large")
        receipt = json.loads(raw)
    except (OSError, ValueError, TypeError):
        raise ActivationBlocked("Cannot read live Identity staging release receipt") from None
    if not isinstance(receipt, dict) or (
        receipt.get("service") != "shadowops-identity"
        or receipt.get("environment") != "staging"
        or not isinstance(receipt.get("source_sha"), str)
        or not SHA.fullmatch(receipt["source_sha"])
    ):
        raise ActivationBlocked("Untrusted Identity release receipt")
    return receipt["source_sha"]


def dispatch_inventory(workflow):
    data = api(
        f"repos/{INFRA}/actions/workflows/{workflow}/runs?"
        "event=workflow_dispatch&per_page=100",
    )
    rows = data.get("workflow_runs")
    if not isinstance(rows, list):
        raise ActivationBlocked("Actions run inventory unavailable")
    return rows


def select_new_run(rows, previous_ids, actor, sha):
    fresh = [
        item for item in rows if isinstance(item, dict)
        and type(item.get("id")) is int and item["id"] not in previous_ids
        and item.get("event") == "workflow_dispatch"
        and item.get("head_sha") == sha
        and (item.get("actor") or {}).get("login") == actor
    ]
    if len(fresh) > 1:
        raise ActivationBlocked("Concurrent matching operator workflows: inspect manually")
    return fresh[0] if fresh else None


def require_job_success(run_id, job_name):
    data = api(f"repos/{INFRA}/actions/runs/{run_id}/jobs?per_page=100")
    rows = data.get("jobs")
    if not isinstance(rows, list):
        raise ActivationBlocked("Missing completed Actions job evidence")
    matches = [
        item for item in rows if isinstance(item, dict)
        and item.get("name") == job_name
    ]
    if len(matches) != 1 or matches[0].get("conclusion") != "success":
        raise ActivationBlocked(f"Protected job {job_name} skipped or failed; stop")
    if any(item.get("conclusion") == "failure" for item in rows):
        raise ActivationBlocked("Other job failure in protected workflow")


def run_protected(workflow, expected_job, actor, infra_sha, inputs=None):
    inputs = inputs or {}
    before = {item.get("id") for item in dispatch_inventory(workflow) if isinstance(item, dict)}
    argv = ["workflow", "run", workflow, "--repo", INFRA, "--ref", "main"]
    for key, value in inputs.items():
        argv.extend(["--field", f"{key}={value}"])
    gh(*argv)
    deadline = time.monotonic() + 120
    receipt = None
    while time.monotonic() < deadline:
        receipt = select_new_run(dispatch_inventory(workflow), before, actor, infra_sha)
        if receipt:
            break
        time.sleep(3)
    if not receipt:
        raise ActivationBlocked("Dispatch submitted but its unique run was not confirmed")
    run_id = receipt["id"]
    print(f"Protected {expected_job} run: https://github.com/{INFRA}/actions/runs/{run_id}", flush=True)
    gh("run", "watch", str(run_id), "--repo", INFRA, "--exit-status", "--interval", "8",
       timeout=2100)
    require_job_success(run_id, expected_job)
    if main_sha(INFRA) != infra_sha:
        raise ActivationBlocked("Infra main advanced during activation")
    print(f"SNOOKER_OPERATOR_{expected_job.upper()}_VERIFIED run={run_id}", flush=True)


def identity_ready():
    # Reuse the exact origin and app-audience check enforced by the publisher.
    from snooker_staging_publish import issuer_ready, ProvisionError
    try:
        issuer_ready()
        return True
    except ProvisionError:
        return False


def source_admitted(game_sha):
    # Exercise the SAME exact-main CI/immutable-artifact gate that the protected
    # publisher will enforce, without holding any GitHub token in Python.
    from snooker_source_admission import admit, AdmissionError

    class OperatorGithubReader:
        def get(self, path):
            return api(path.removeprefix("/"))

    try:
        return admit(OperatorGithubReader(), game_sha)
    except AdmissionError:
        raise ActivationBlocked("Current Snooker main CI/artifact is not admissible") from None


def preflight(identity_sha):
    """Read-only; never provision a Vault consumer before resolving blockers."""
    if identity_sha is not None and not SHA.fullmatch(identity_sha):
        raise ActivationBlocked("Provide a lowercase 40-hex Identity image source SHA")
    actor = api("user").get("login")
    if not isinstance(actor, str) or not actor:
        raise ActivationBlocked("Authenticated gh operator identity unavailable")
    infra_sha = main_sha(INFRA)
    game_sha = main_sha(GAME)
    admission = source_admitted(game_sha)
    ready = identity_ready()
    selected_sha = identity_sha
    if not ready and selected_sha is None:
        selected_sha = latest_identity_image_sha()
    if selected_sha is not None:
        no_downgrade(deployed_identity_sha(), selected_sha)
    if main_sha(INFRA) != infra_sha or main_sha(GAME) != game_sha:
        raise ActivationBlocked("Source main advanced during read-only preflight")
    print("SNOOKER_OPERATOR_PREFLIGHT_OK writes=false game_sha=" + game_sha
          + " ci_run=" + str(admission["run_id"])
          + " identity_ready=" + str(ready).lower()
          + " identity_image_sha=" + (selected_sha or "not-needed"), flush=True)
    return actor, infra_sha, game_sha, selected_sha


def activate(identity_sha):
    actor, infra_sha, game_sha, selected_sha = preflight(identity_sha)
    run_protected(IDENTITY_WORKFLOW, "provision", actor, infra_sha,
                  {"action": "provision", "snooker_consumer": "enable"})

    if not identity_ready():
        if not selected_sha:
            raise ActivationBlocked("Identity image unexpectedly missing after preflight")
        run_protected(IDENTITY_WORKFLOW, "deploy", actor, infra_sha,
                      {"action": "deploy", "source_sha": selected_sha})
        if not identity_ready():
            raise ActivationBlocked("Deployed Identity still does not recognize Snooker")

    if main_sha(GAME) != game_sha:
        raise ActivationBlocked("Game main advanced during activation; re-admit new source")
    run_protected(PAGES_WORKFLOW, "publish", actor, infra_sha)
    print(
        "SNOOKER_STAGING_GUEST_GATE_COMPLETE "
        f"game_sha={game_sha} authenticated_browser_acceptance=pending",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Snooker staging — protected operator handoff")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true",
                      help="Explicitly dispatch protected workflows via your own gh auth")
    mode.add_argument("--check", action="store_true",
                      help="Read-only source/Identity/image discovery gate before provisioning")
    parser.add_argument("--identity-sha", default=None,
                        help="Override auto-discovery with a pinned Identity image SHA")
    args = parser.parse_args()
    if not args.apply and not args.check:
        print("SNOOKER_OPERATOR_PLAN writes=false")
        print("Requires gh auth with Actions write permission and protected staging approval.")
        print("On --apply: provision isolated Snooker audience; deploy only if not active; "
              "publish SHA-admitted Pages; verify protected job completion.")
        print("A live signed-in/revoked-session WebGL acceptance remains separate.")
        return 0
    try:
        if args.check:
            preflight(args.identity_sha)
        else:
            activate(args.identity_sha)
        return 0
    except ActivationBlocked as exc:
        print("SNOOKER_OPERATOR_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
