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


def scheduled_today(runs: list, now: datetime) -> int | None:
    """Return a genuine schedule run created at/after 07:45 Madrid today."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ScheduleError("timezone-aware clock required")
    local = now.astimezone(ZONE)
    earliest = datetime.combine(local.date(), time(7, 45), tzinfo=ZONE)
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
        if (created.tzinfo is not None
                and earliest <= created.astimezone(ZONE) <= local):
            return run_id
    return None


def main() -> int:
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != REPO
                or os.environ.get("GITHUB_EVENT_NAME") != "schedule"
                or os.environ.get("GITHUB_REF") != "refs/heads/main"):
            raise ScheduleError("scheduled audit main only")
        token = os.environ.get("GH_TOKEN", "")
        run_id = scheduled_today(fetch_runs(token), datetime.now(timezone.utc))
        if run_id is None:
            raise ScheduleError("no release train schedule run today")
    except (ScheduleError, urllib.error.URLError, ValueError, TypeError,
            OSError, TimeoutError):
        # No secrets or raw provider responses in logs.
        print("CHRONICLES_TRAIN_SCHEDULE_NOT_OBSERVED", file=sys.stderr)
        return 1
    print("CHRONICLES_TRAIN_SCHEDULE_OBSERVED run=" + str(run_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
