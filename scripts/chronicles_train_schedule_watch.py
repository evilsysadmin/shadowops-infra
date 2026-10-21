#!/usr/bin/env python3
"""Observe a scheduled Chronicles release train; never trigger or mutate it.

The daily production audit must not be green solely because yesterday's
production release still serves traffic when today's train never started.
"""
from __future__ import annotations

from datetime import datetime, time, timezone
import json
import os
import sys
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

REPO = "evilsysadmin/shadowops-infra"
WORKFLOW = ".github/workflows/chronicles-production-train.yml"
ZONE = ZoneInfo("Europe/Madrid")
URL = ("https://api.github.com/repos/" + REPO
       + "/actions/workflows/chronicles-production-train.yml/runs"
       + "?event=schedule&per_page=10")


class ScheduleError(RuntimeError):
    pass


def fetch_runs(token: str, *, opener=urllib.request.urlopen) -> list:
    if not token:
        raise ScheduleError("missing read-only GitHub token")
    request = urllib.request.Request(URL, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ChroniclesTrainScheduleWatch/1",
    })
    with opener(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != URL:
            raise ScheduleError("unexpected workflow evidence origin")
        raw = response.read(256001)
    if len(raw) > 256000:
        raise ScheduleError("workflow evidence too large")
    payload = json.loads(raw)
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list) or len(runs) > 10:
        raise ScheduleError("invalid scheduled workflow evidence")
    return runs


TRAIN_JOB = "Admit staging, promote API, promote Pages, verify public release"
TRAIN_STEP = "Promote only admitted source, stop if API/Pages fail"


def fetch_train_jobs(run_id: int, token: str, *, opener=urllib.request.urlopen) -> list:
    """Read the actual jobs, not just the overall workflow conclusion."""
    if not token or type(run_id) is not int or run_id <= 0:
        raise ScheduleError("invalid run evidence request")
    url = (f"https://api.github.com/repos/{REPO}/actions/runs/"
           f"{run_id}/jobs?per_page=100")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ChroniclesTrainScheduleWatch/1",
    })
    with opener(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != url:
            raise ScheduleError("unexpected child-job evidence origin")
        raw = response.read(512001)
    if len(raw) > 512000:
        raise ScheduleError("child-job evidence too large")
    payload = json.loads(raw)
    jobs = payload.get("jobs") if isinstance(payload, dict) else None
    if (not isinstance(jobs, list) or len(jobs) > 100
            or payload.get("total_count", 0) > 100):
        raise ScheduleError("incomplete child-job evidence")
    return jobs


def train_job_succeeded(jobs: list) -> bool:
    """Only a successful *executed* promotion step proves the train ran."""
    candidates = [job for job in jobs if isinstance(job, dict)
                  and job.get("name") == TRAIN_JOB]
    if len(candidates) != 1:
        return False
    job = candidates[0]
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        return False
    steps = job.get("steps")
    return isinstance(steps, list) and any(
        isinstance(step, dict)
        and step.get("name") == TRAIN_STEP
        and step.get("status") == "completed"
        and step.get("conclusion") == "success" for step in steps
    )


def latest_scheduled_run(runs: list, now: datetime) -> dict | None:
    """Select today's latest authentic 08:00 Madrid schedule event."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ScheduleError("timezone-aware clock required")
    local = now.astimezone(ZONE)
    earliest = datetime.combine(local.date(), time(7, 45), tzinfo=ZONE)
    latest = None
    for run in runs:
        if not isinstance(run, dict):
            continue
        run_id = run.get("id")
        if (type(run_id) is not int or run_id <= 0
                or run.get("event") != "schedule"
                or run.get("path") != WORKFLOW
                or run.get("head_branch") != "main"
                or (run.get("repository") or {}).get("full_name") != REPO):
            continue
        try:
            created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        except (KeyError, AttributeError, TypeError, ValueError):
            continue
        if created.tzinfo is None:
            continue
        timestamp = created.astimezone(ZONE)
        if earliest <= timestamp <= local:
            if latest is None or (timestamp, run_id) > (latest[0], latest[1]["id"]):
                latest = (timestamp, run)
    return latest[1] if latest else None


def scheduled_today(runs: list, now: datetime) -> int | None:
    """Backward-compatible existence check for contract consumers."""
    run = latest_scheduled_run(runs, now)
    return run["id"] if run is not None else None


def completed_train_today(runs: list, now: datetime) -> int:
    """A past healthy production build cannot mask a failed/stalled train."""
    run = latest_scheduled_run(runs, now)
    if run is None:
        raise ScheduleError("NOT_OBSERVED")
    if run.get("status") != "completed":
        raise ScheduleError("INCOMPLETE")
    if run.get("conclusion") != "success":
        raise ScheduleError("FAILED")
    return run["id"]


def main() -> int:
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != REPO
                or os.environ.get("GITHUB_EVENT_NAME") != "schedule"
                or os.environ.get("GITHUB_REF") != "refs/heads/main"):
            raise ScheduleError("scheduled audit main only")
        token = os.environ.get("GH_TOKEN", "")
        run_id = completed_train_today(fetch_runs(token), datetime.now(timezone.utc))
        if not train_job_succeeded(fetch_train_jobs(run_id, token)):
            raise ScheduleError("JOB_NOT_SUCCESSFUL")
    except (ScheduleError, urllib.error.URLError, ValueError, TypeError,
            OSError, TimeoutError) as exc:
        # Only emit known states, never raw provider errors or responses.
        state = (str(exc) if isinstance(exc, ScheduleError)
                 and str(exc) in {"NOT_OBSERVED", "INCOMPLETE", "FAILED", "JOB_NOT_SUCCESSFUL"}
                 else "EVIDENCE_UNAVAILABLE")
        print("CHRONICLES_TRAIN_SCHEDULE_" + state, file=sys.stderr)
        return 1
    print("CHRONICLES_TRAIN_SCHEDULE_SUCCESS run=" + str(run_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
