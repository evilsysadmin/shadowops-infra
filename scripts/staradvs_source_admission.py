#!/usr/bin/env python3
"""Admit Star Adventures main SHA only after its exact CI push run is green."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = "evilsysadmin/star-adventures"
RUN_WORKFLOW = "ci.yml"
NEEDED = {"Core rules and episode tests", "React build and browser smoke"}
HEX = re.compile(r"^[a-f0-9]{40}$")


class SourceAdmissionError(Exception):
    pass


class GithubReader:
    def __init__(self, token: str):
        if not token:
            raise SourceAdmissionError("GH_TOKEN is required for independent CI evidence")
        self.token = token

    def get(self, path: str):
        if not path.startswith("/repos/" + REPO + "/") or ".." in path:
            raise SourceAdmissionError("Source evidence path outside allowlist")
        req = urllib.request.Request(
            "https://api.github.com" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise SourceAdmissionError("GitHub source evidence HTTP not 200")
                return json.loads(response.read(2_000_000))
        except (urllib.error.URLError, ValueError, UnicodeError) as exc:
            raise SourceAdmissionError("GitHub source evidence unavailable: " + type(exc).__name__) from None


def admit(reader, source_sha: str):
    if not HEX.fullmatch(source_sha):
        raise SourceAdmissionError("Not an immutable full source SHA")
    current = reader.get(f"/repos/{REPO}/commits/main")
    if not isinstance(current, dict) or current.get("sha") != source_sha:
        raise SourceAdmissionError("Candidate is not current source main")
    query = urllib.parse.urlencode({"branch": "main", "head_sha": source_sha, "per_page": "50"})
    data = reader.get(f"/repos/{REPO}/actions/workflows/{RUN_WORKFLOW}/runs?" + query)
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        raise SourceAdmissionError("Cannot enumerate source CI runs")
    matches = [run for run in runs if isinstance(run, dict) and
               run.get("head_sha") == source_sha and run.get("event") == "push" and
               run.get("head_branch") == "main" and run.get("status") == "completed" and
               run.get("conclusion") == "success"]
    for run in matches:
        rid = run.get("id")
        if not isinstance(rid, int):
            continue
        response = reader.get(f"/repos/{REPO}/actions/runs/{rid}/jobs?per_page=100")
        jobs = response.get("jobs") if isinstance(response, dict) else None
        if not isinstance(jobs, list):
            continue
        # GitHub occasionally reports status='in_progress' for a finished job,
        # while already providing conclusion='success' and completed_at. Accept
        # only that documented inconsistency within a completed successful RUN.
        # Pending, uncompleted, cancelled or failed jobs are never evidence.
        passed = {job.get("name") for job in jobs if isinstance(job, dict) and
                  job.get("conclusion") == "success" and
                  job.get("status") in ("completed", "in_progress") and
                  isinstance(job.get("completed_at"), str) and
                  bool(job["completed_at"])}
        if NEEDED.issubset(passed):
            return rid
    raise SourceAdmissionError("Exact source-main CI core and Chrome jobs not yet green")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: staradvs_source_admission.py <exact-40-hex-main-sha>")
    try:
        source_sha = sys.argv[1]
        run_id = admit(GithubReader(os.environ.get("GH_TOKEN", "")), source_sha)
        print(f"STARADVS_SOURCE_CI_ADMITTED sha={source_sha} run_id={run_id}")
        return 0
    except SourceAdmissionError as exc:
        print("STARADVS_SOURCE_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
