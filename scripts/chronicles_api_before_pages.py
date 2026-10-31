#!/usr/bin/env python3
"""Fail-closed staging handoff: do not publish a Chronicles client before its API.

Trust only a successful Infra API workflow run on main carrying the exact
source-SHA receipt written after OCI health, public smoke and account E2E.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from chronicles_staging_receipt import ReceiptError, trusted_staging_receipt

INFRA = "evilsysadmin/shadowops-infra"
SOURCE = "evilsysadmin/chronicles-of-matthias"
API_WORKFLOW = ".github/workflows/chronicles-api-staging.yml"
SHA = re.compile(r"^[0-9a-f]{40}$")
API_ORIGIN = "https://chronicles-api-staging.shadowops.dpdns.org/api"


class GateError(RuntimeError):
    pass


def fetch(path: str, token: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise GateError("Cannot read GitHub deployment evidence") from exc
    if not isinstance(result, dict):
        raise GateError("Malformed GitHub evidence")
    return result


def evidence_ok(sha: str, listing: dict, read_run) -> bool:
    """Validate API receipts using the shared fixed-workflow identity contract."""
    try:
        return trusted_staging_receipt(sha, listing, read_run, kind="api")
    except ReceiptError as exc:
        if not SHA.fullmatch(sha):
            raise GateError("Invalid source SHA") from exc
        if "artifact listing" in str(exc):
            raise GateError("Missing deployment artifacts") from exc
        raise GateError(str(exc)) from exc

def api_receipt_available(sha: str, token: str, *, get=fetch) -> bool:
    """Single, trusted exact-SHA receipt check shared by API admission and Pages."""
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing read token or invalid source SHA")
    path = f"repos/{INFRA}/actions/artifacts?" + urllib.parse.urlencode(
        {"name": "chronicles-api-staging-" + sha, "per_page": 100}
    )
    return evidence_ok(
        sha, get(path, token),
        lambda run_id: get(f"repos/{INFRA}/actions/runs/{run_id}", token),
    )


def probe_public(path: str) -> bool:
    """Require the exact HTTPS API origin, never a redirected healthy server."""
    if path not in {"health", "ready"}:
        return False
    url = API_ORIGIN + "/" + path
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-api-admission/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status == 200 and response.geturl() == url
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError):
        return False


def public_api_healthy(*, probe=probe_public, sleep=time.sleep) -> bool:
    """Retry each public endpoint once; never redeploy on inconclusive health."""
    for path in ("health", "ready"):
        if probe(path):
            continue
        sleep(2)
        if not probe(path):
            return False
    return True


def read_public_build(*, opener=urllib.request.urlopen) -> str | None:
    """Read the revision actually served by the staging API; never trust the receipt alone."""
    request = urllib.request.Request(
        API_ORIGIN + "/release?sha_check=" + str(time.time_ns()),
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-api-admission/1"},
    )
    try:
        with opener(request, timeout=10) as response:
            # A 200 from another host (or another API path) is not evidence
            # of the deployed staging binary, even with a plausible SHA.
            if (response.status != 200
                    or response.geturl().partition("?")[0] != API_ORIGIN + "/release"):
                return None
            raw = response.read(4097)
        if len(raw) > 4096:
            return None
        data = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError,
            UnicodeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("build")
    return value if isinstance(value, str) and SHA.fullmatch(value) else None


def public_api_revision_state(sha: str, *, read=read_public_build) -> str:
    """match, different, unknown; unknown must not trigger automatic redeployment."""
    if not SHA.fullmatch(sha):
        raise GateError("Invalid source SHA")
    live = read()
    return "unknown" if live is None else ("match" if live == sha else "different")


def wait_for_api(sha: str, token: str, *, attempts: int = 49, sleep=time.sleep,
                 get=fetch, healthy=public_api_healthy,
                 revision=public_api_revision_state) -> None:
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing read token or invalid source SHA")
    for attempt in range(attempts):
        current = get(f"repos/{SOURCE}/commits/main", token).get("sha")
        if current != sha:
            raise GateError("CHRONICLES_PAGES_STALE_SOURCE_BLOCKED")
        if api_receipt_available(sha, token, get=get):
            # A past OCI/E2E receipt must not permit Pages mutations while the
            # actual public API is degraded. Retry on the next admitted run.
            if not healthy():
                raise GateError("CHRONICLES_API_PUBLIC_HEALTH_UNAVAILABLE")
            state = revision(sha)
            if state != "match":
                raise GateError("CHRONICLES_API_PUBLIC_SOURCE_" +
                                ("MISMATCH" if state == "different" else "INCONCLUSIVE"))
            print("CHRONICLES_API_VERIFIED_BEFORE_PAGES sha=" + sha)
            return
        if attempt + 1 < attempts:
            print("CHRONICLES_API_RECEIPT_PENDING attempt=" + str(attempt + 1), flush=True)
            sleep(15)
    raise GateError("CHRONICLES_API_RECEIPT_TIMEOUT")


def main() -> int:
    token = os.environ.get("GH_TOKEN", "")
    if len(sys.argv) == 3 and sys.argv[1] == "--public-sha-only":
        try:
            state = public_api_revision_state(sys.argv[2])
            if state == "match":
                print("CHRONICLES_API_PUBLIC_SOURCE_OK sha=" + sys.argv[2])
                return 0
            print("CHRONICLES_API_PUBLIC_SOURCE_" +
                  ("MISMATCH" if state == "different" else "INCONCLUSIVE"),
                  file=sys.stderr)
            return 1 if state == "different" else 2
        except GateError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    if len(sys.argv) == 3 and sys.argv[1] == "--receipt-only":
        try:
            if not api_receipt_available(sys.argv[2], token):
                return 1  # No trusted receipt: normal deploy admission may proceed.
            if not public_api_healthy():
                print("CHRONICLES_API_RECEIPT_LIVE_HEALTH_INCONCLUSIVE", file=sys.stderr)
                return 2  # Do not redeploy automatically on a transient/outage.
            state = public_api_revision_state(sys.argv[2])
            if state == "unknown":
                print("CHRONICLES_API_PUBLIC_SOURCE_INCONCLUSIVE", file=sys.stderr)
                return 2
            if state == "different":
                print("CHRONICLES_API_PUBLIC_SOURCE_MISMATCH", file=sys.stderr)
                return 1  # Confirmed drift: guarded admission may restore current SHA.
            print("CHRONICLES_API_STAGING_ALREADY_VERIFIED sha=" + sys.argv[2])
            return 0
        except GateError as exc:
            print(str(exc), file=sys.stderr)
            return 2  # Inconclusive: do not deploy or falsely claim verification.
    if len(sys.argv) != 2:
        return 64
    try:
        wait_for_api(sys.argv[1], token)
        return 0
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
