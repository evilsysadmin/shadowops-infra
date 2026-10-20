#!/usr/bin/env python3
"""Low-noise Chronicles staging watch: two probes, one actionable GitHub issue.

Checks public health unconditionally. Reports version drift only after the
source SHA has all three green push workflows and a 90-minute deploy grace.
No secrets outside the GitHub token are needed.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

import chronicles_source_ci as ci
import chronicles_api_before_pages as receipts

INFRA = "evilsysadmin/shadowops-infra"
TITLE = "[staging-watch] Chronicles staging necesita atención"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
API = "https://chronicles-api-staging.shadowops.dpdns.org/api"
GRACE_SECONDS = 90 * 60


def get_url(url: str, token: str = "") -> dict:
    headers = {"Accept": "application/vnd.github+json" if token else "application/json",
               "User-Agent": "shadowops-chronicles-watch/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
    if not isinstance(data, dict):
        raise ValueError("Expected object response")
    return data


def github(path: str, token: str, *, method="GET", payload=None) -> dict:
    url = "https://api.github.com/" + path
    if method == "GET":
        return get_url(url, token)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "User-Agent": "shadowops-chronicles-watch/1"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def failures(token: str, *, get: Callable = get_url, gh: Callable = github,
             now: dt.datetime | None = None) -> dict[str, str]:
    now = now or dt.datetime.now(dt.timezone.utc)
    bad = {}
    try:
        get(API + "/health")
        get(API + "/ready")
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        bad["api-health"] = "La API pública /health o /ready no responde correctamente"
    try:
        manifest = get(ORIGIN + "/release.json?watch=" + str(int(now.timestamp())))
        live_sha = manifest.get("build")
        if not isinstance(live_sha, str) or not ci.SHA.fullmatch(live_sha):
            bad["pages-manifest"] = "El release.json público no expone un SHA válido"
            live_sha = None
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        bad["pages-manifest"] = "El release.json público no es accesible"
        live_sha = None

    source = gh("repos/" + ci.SOURCE + "/commits/main", token)
    source_sha = source.get("sha")
    if not isinstance(source_sha, str) or not ci.SHA.fullmatch(source_sha):
        raise RuntimeError("Cannot verify protected Chronicles source")
    verdict = ci.inspect(source_sha, token)
    if verdict != "ready":
        # Do not complain about an unshipped or unfinished source commit.
        return bad

    stamp = (source.get("commit") or {}).get("committer", {}).get("date", "")
    try:
        age = (now - dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
    except (TypeError, ValueError):
        raise RuntimeError("Cannot date the verified source main")
    if age < GRACE_SECONDS:
        return bad
    if live_sha != source_sha:
        bad["frontend-lag"] = "Pages no publica el último SHA verde después del margen de 90 minutos"

    try:
        listing = gh("repos/" + INFRA + "/actions/artifacts?name=chronicles-api-staging-" + source_sha + "&per_page=100", token)
        if not receipts.evidence_ok(source_sha, listing,
                lambda rid: gh("repos/" + INFRA + "/actions/runs/" + str(rid), token)):
            bad["backend-lag"] = "No hay recibo válido de OCI/E2E para el SHA verde"
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        raise RuntimeError("Cannot verify staging deployment receipt")
    return bad


def existing_issue(token: str, gh: Callable = github) -> int | None:
    data = gh("repos/" + INFRA + "/issues?state=open&per_page=100", token)
    # GitHub's REST issues endpoint returns an array; wrapper normalizes it.
    rows = data if isinstance(data, list) else data.get("items", [])
    for entry in rows:
        if entry.get("title") == TITLE and not entry.get("pull_request"):
            return entry["number"]
    return None


def manage_issue(token: str, persistent: dict[str, str], *, gh: Callable = github) -> str:
    issue = existing_issue(token, gh=gh)
    if not persistent:
        if issue is not None:
            gh(f"repos/{INFRA}/issues/{issue}", token, method="PATCH",
               payload={"state": "closed", "state_reason": "completed"})
            return "CHRONICLES_STAGING_WATCH_RECOVERED"
        return "CHRONICLES_STAGING_WATCH_OK"
    if issue is not None:
        return "CHRONICLES_STAGING_WATCH_ALREADY_OPEN"
    details = "\n".join("- **" + key + "**: " + reason for key, reason in persistent.items())
    body = ("Detectado en dos comprobaciones separadas. Estado público, sin datos de usuarios.\n\n" +
            details + "\n\nRevisar los workflows en https://github.com/" + INFRA +
            "/actions y los SHA publicados. Esta incidencia se cerrará automáticamente cuando el staging se recupere.")
    gh(f"repos/{INFRA}/issues", token, method="POST",
       payload={"title": TITLE, "body": body})
    return "CHRONICLES_STAGING_WATCH_ISSUE_OPENED"


def main() -> int:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("Missing GitHub token", file=sys.stderr)
        return 2
    try:
        first = failures(token)
        if first:
            print("CHRONICLES_STAGING_WATCH_RECHECK " + ",".join(sorted(first)), flush=True)
            time.sleep(90)
            second = failures(token)
            # Alert only issues present in both samples, not short-lived errors.
            persistent = {k: second[k] for k in first.keys() & second.keys()}
        else:
            persistent = {}
        print(manage_issue(token, persistent))
        return 0
    except Exception as exc:
        # A broken watchdog must not create a false outage or leak credentials.
        print("CHRONICLES_STAGING_WATCH_INCONCLUSIVE " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
