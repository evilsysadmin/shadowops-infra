"""Pin the exact *forward* Pages deployment before any staging recovery.

Cloudflare canonical_deployment is the active production-branch Pages revision.
Its SHA, immutable origin, and GitHub verified release receipt must independently
agree with the public staging site. This module performs only GET requests.
"""
from __future__ import annotations

import staradvs_pages as pages
from staradvs_rollback_inventory import valid_deployment
from staradvs_immutable_target import verify_immutable_target
from staradvs_rollback_evidence import (
    OWNER, RUNS_PATH, credible_receipt, credible_run,
)


def canonical_forward(client, public_sha: str) -> dict:
    if not isinstance(public_sha, str) or not pages.SHA_PATTERN.fullmatch(public_sha):
        raise pages.AdmissionError("Invalid public staging baseline SHA")
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"
    code, project = client.request("GET", path)
    if (code != 200 or not isinstance(project, dict)
            or project.get("name") != pages.PROJECT
            or project.get("production_branch") != "main"):
        raise pages.AdmissionError("Forward baseline Pages project mismatched")
    canonical = project.get("canonical_deployment")
    verified = valid_deployment(canonical)
    if verified is None or verified["source_sha"] != public_sha:
        raise pages.AdmissionError("Forward Pages canonical deployment does not match public SHA")
    origin = verify_immutable_target(canonical, public_sha)
    return {
        "forward_deployment_id": verified["deployment_id"],
        "forward_sha": public_sha,
        "forward_immutable_url": origin,
    }


def forward_release_receipt(reader, sha: str) -> dict:
    if not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha):
        raise pages.AdmissionError("Invalid forward SHA")
    runs_data = reader.get(RUNS_PATH)
    runs = runs_data.get("workflow_runs")
    if not isinstance(runs, list):
        raise pages.AdmissionError("Forward publisher history unavailable")
    for run in [x for x in runs[:100] if credible_run(x)][:40]:
        rid = run["id"]
        artifact_path = f"/repos/{OWNER}/actions/runs/{rid}/artifacts?per_page=100"
        data = reader.get(artifact_path)
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list):
            raise pages.AdmissionError("Forward publisher artifact list unavailable")
        match = next((x for x in artifacts if credible_receipt(x, rid, sha)), None)
        if match is not None:
            return {
                "forward_publish_run_id": rid,
                "forward_receipt_id": match["id"],
            }
    raise pages.AdmissionError("Forward canonical Pages SHA lacks unexpired Infra publish receipt")
