"""Read-only GitHub Actions receipt cross-check for Pages staging rollback candidates.

A candidate is a possible *plan*, never permission to mutate Pages.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

import staradvs_pages as pages

OWNER = "evilsysadmin/shadowops-infra"
WORKFLOW = ".github/workflows/staradvs-pages-staging.yml"
RUNS_PATH = f"/repos/{OWNER}/actions/workflows/staradvs-pages-staging.yml/runs?per_page=100"
ARTIFACT_PATH = re.compile(r"^/repos/evilsysadmin/shadowops-infra/actions/runs/([0-9]+)/artifacts\?per_page=100$")


class GitHubEvidence:
    def __init__(self, token: str):
        if not token:
            raise pages.AdmissionError("Missing GitHub Actions read-only evidence token")
        self.token = token

    def get(self, path: str):
        if path != RUNS_PATH and not ARTIFACT_PATH.fullmatch(path):
            raise pages.AdmissionError("Unexpected GitHub evidence endpoint")
        req = urllib.request.Request("https://api.github.com" + path, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise pages.AdmissionError("GitHub release evidence not HTTP 200")
                data = json.loads(response.read(2_000_001))
        except (urllib.error.URLError, ValueError, UnicodeError) as exc:
            raise pages.AdmissionError("GitHub release evidence unavailable (" + type(exc).__name__ + ")") from None
        if not isinstance(data, dict):
            raise pages.AdmissionError("GitHub release evidence is not an object")
        return data


def credible_run(run: object) -> bool:
    if not isinstance(run, dict):
        return False
    repo = run.get("repository")
    return (
        type(run.get("id")) is int and run["id"] > 0
        and run.get("path") == WORKFLOW
        and run.get("head_branch") == "main"
        and run.get("event") in ("push", "workflow_dispatch", "schedule")
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and isinstance(run.get("head_sha"), str)
        and bool(pages.SHA_PATTERN.fullmatch(run["head_sha"]))
        and isinstance(repo, dict) and repo.get("full_name") == OWNER
    )


def credible_receipt(artifact: object, run_id: int, sha: str) -> bool:
    if not isinstance(artifact, dict):
        return False
    link = artifact.get("workflow_run")
    return (
        type(artifact.get("id")) is int and artifact["id"] > 0
        and artifact.get("name") == "staradvs-staging-verified-" + sha
        and artifact.get("expired") is False
        and isinstance(link, dict) and link.get("id") == run_id
        and isinstance(artifact.get("size_in_bytes"), int) and artifact["size_in_bytes"] > 0
    )


def corroborate(report: dict, reader: GitHubEvidence) -> dict:
    """Correlate source SHA with prior green Infra publish and unexpired receipt."""
    candidates = report.get("potential_previous")
    if not isinstance(candidates, list):
        raise pages.AdmissionError("Pages candidate inventory absent")
    sha = report.get("live_sha")
    if not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha):
        raise pages.AdmissionError("Public live SHA unavailable")
    for candidate in candidates:
        if (not isinstance(candidate, dict)
                or not isinstance(candidate.get("source_sha"), str)
                or not pages.SHA_PATTERN.fullmatch(candidate["source_sha"])
                or candidate["source_sha"] == sha):
            raise pages.AdmissionError("Untrusted rollback candidate data")
    data = reader.get(RUNS_PATH)
    runs = data.get("workflow_runs")
    if not isinstance(runs, list):
        raise pages.AdmissionError("GitHub staging runs unavailable")
    # Bounded result set, with no inferred success if archived Actions metadata is missing.
    selected = [run for run in runs[:100] if credible_run(run)][:40]
    verified = []
    remaining = {p["source_sha"]: p for p in candidates[:5]}
    for run in selected:
        if not remaining:
            break
        rid = run["id"]
        artifacts = reader.get(f"/repos/{OWNER}/actions/runs/{rid}/artifacts?per_page=100")
        entries = artifacts.get("artifacts")
        if not isinstance(entries, list):
            raise pages.AdmissionError("GitHub release artifacts cannot be checked")
        for previous_sha, candidate in list(remaining.items()):
            match = next((a for a in entries if credible_receipt(a, rid, previous_sha)), None)
            if match is not None:
                verified.append({
                    **candidate,
                    "infra_publish_run_id": rid,
                    "verified_receipt_id": match["id"],
                })
                del remaining[previous_sha]
    report = dict(report)
    report["receipt_backed_previous"] = verified
    report["receipt_verification"] = "GET-only GitHub artifact evidence; not an executed rollback"
    if candidates and not verified:
        raise pages.AdmissionError("No previous Pages revision has a valid GitHub release receipt")
    return report
