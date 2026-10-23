#!/usr/bin/env python3
"""GET-only Cloudflare Pages staging rollback inventory. NEVER executes rollback."""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.request
from uuid import UUID

import staradvs_pages as pages


def valid_deployment(row: object) -> dict | None:
    if not isinstance(row, dict):
        return None
    try:
        deployment_id = str(UUID(row["id"]))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if deployment_id != row["id"] or row.get("project_name") != pages.PROJECT:
        return None
    if row.get("environment") != "production":  # Pages production branch, NOT game production DNS.
        return None
    stage = row.get("latest_stage")
    if not isinstance(stage, dict) or stage.get("status") != "success":
        return None
    trigger = row.get("deployment_trigger")
    metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    if not isinstance(metadata, dict):
        return None
    sha = metadata.get("commit_hash")
    if (not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha)
            or metadata.get("branch") != "main" or metadata.get("commit_dirty") is not False):
        return None
    created = row.get("created_on")
    if not isinstance(created, str) or not re.match(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T", created):
        return None
    return {"deployment_id": deployment_id, "source_sha": sha, "created_on": created}


def select_candidates(rows: object, live_sha: str) -> dict:
    if not pages.SHA_PATTERN.fullmatch(live_sha):
        raise pages.AdmissionError("Published staging source SHA missing or invalid")
    if not isinstance(rows, list):
        raise pages.AdmissionError("Pages deployments inventory is not a list")
    # The API's first production page may include malformed/foreign/preview
    # records; they are NEVER promoted to rollback candidates.
    valid = [p for row in rows if (p := valid_deployment(row)) is not None]
    current = [p for p in valid if p["source_sha"] == live_sha]
    if not current:
        raise pages.AdmissionError("Live staging SHA absent from owned successful production deployments")
    valid.sort(key=lambda p: p["created_on"], reverse=True)
    seen = {live_sha}
    previous = []
    for p in valid:
        if p["source_sha"] in seen:
            continue
        seen.add(p["source_sha"])
        previous.append(p)
    return {
        "live_sha": live_sha,
        "matching_live_deployments": len(current),
        "potential_previous": previous[:5],
        "scope": "read-only, candidates unapproved; Pages production BRANCH on staging project only",
        "incomplete_history_possible": True,  # Only first page queried.
    }


def public_sha() -> str:
    url = pages.BASE + "/release.json"
    request = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                raise pages.AdmissionError("Public staging manifest redirected or non-200")
            if "json" not in response.headers.get("Content-Type", "").lower():
                raise pages.AdmissionError("Public staging manifest MIME invalid")
            raw = response.read(65537)
    except (OSError, TimeoutError) as exc:
        raise pages.AdmissionError("Public staging manifest unavailable (" + type(exc).__name__ + ")") from None
    if not raw or len(raw) > 65536:
        raise pages.AdmissionError("Public staging manifest size invalid")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        raise pages.AdmissionError("Public staging manifest JSON invalid") from None
    if not isinstance(obj, dict) or obj.get("environment") != "staging":
        raise pages.AdmissionError("Public staging identity mismatch")
    sha = obj.get("build")
    if not isinstance(sha, str) or not pages.SHA_PATTERN.fullmatch(sha):
        raise pages.AdmissionError("Public staging source SHA missing")
    # The existing live TLS/HTML/JS SHA-256 probe is the source of truth.
    pages.public_check(sha)
    return sha


def inventory(client, live_sha: str) -> dict:
    _, owners = pages.inspect(client)
    if owners != {"project": "owned", "domain": "owned", "dns": "owned"}:
        raise pages.AdmissionError("Pages staging identity is not completely owned")
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments?env=production&per_page=50&page=1"
    code, rows = client.request("GET", path)
    if code != 200:
        raise pages.AdmissionError("Pages deployment inventory unreadable")
    return select_candidates(rows, live_sha)


def main() -> int:
    try:
        live_sha = public_sha()
        client = pages.CloudflareClient(os.environ)
        report = inventory(client, live_sha)
        print("STARADVS_STAGING_ROLLBACK_READONLY_PLAN " + json.dumps(report, sort_keys=True))
        return 0
    except pages.AdmissionError as exc:
        print("STARADVS_STAGING_ROLLBACK_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
