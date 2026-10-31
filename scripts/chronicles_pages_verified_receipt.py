#!/usr/bin/env python3
"""Skip a staging Pages deployment only when its receipt AND live HTTPS build agree."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from chronicles_api_before_pages import GateError, INFRA, SHA, fetch
from chronicles_staging_receipt import ReceiptError, trusted_staging_receipt

PAGES_WORKFLOW = ".github/workflows/chronicles-pages-release.yml"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
MAX_MANIFEST_BYTES = 4096


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect, even to another valid JSON manifest, is not evidence
        # that Chronicles staging is serving the requested release itself.
        return None


def receipt_ok(sha: str, listing: dict, read_run) -> bool:
    """Validate Pages receipts using the same fixed-workflow identity contract."""
    try:
        return trusted_staging_receipt(sha, listing, read_run, kind="pages")
    except ReceiptError as exc:
        if "artifact listing" in str(exc):
            raise GateError("Malformed Pages artifact listing") from exc
        raise GateError(str(exc)) from exc

def read_manifest(url: str, *, opener=None) -> dict:
    """Require bounded JSON served directly from the exact staging hostname."""
    parsed = urllib.parse.urlsplit(url)
    expected = urllib.parse.urlsplit(ORIGIN)
    if (parsed.scheme != "https" or parsed.netloc != expected.netloc
            or parsed.path != "/release.json" or not parsed.query
            or parsed.fragment):
        raise ValueError("Untrusted Chronicles public manifest target")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-pages-receipt/1"},
    )
    transport = opener or urllib.request.build_opener(_NoRedirect()).open
    with transport(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("Chronicles public manifest origin/status mismatch")
        content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0].strip().lower()
        if content_type != "application/json" and not (
                content_type.startswith("application/") and content_type.endswith("+json")):
            raise ValueError("Chronicles public manifest is not JSON")
        raw = response.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Chronicles public manifest exceeds size limit")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Chronicles public manifest must be a JSON object")
    return data


def verified_live(sha: str, token: str, *, get=fetch, public=read_manifest) -> bool:
    if not SHA.fullmatch(sha) or not token:
        raise GateError("Missing token or invalid Chronicles source SHA")
    path = "repos/" + INFRA + "/actions/artifacts?" + urllib.parse.urlencode(
        {"name": "chronicles-pages-staging-" + sha, "per_page": 100}
    )
    if not receipt_ok(sha, get(path, token),
                      lambda run_id: get(f"repos/{INFRA}/actions/runs/{run_id}", token)):
        return False
    return live_matches(sha, public=public)


def live_matches(sha: str, *, public=read_manifest) -> bool:
    """Public-SHA probe only; never replaces trusted receipt and CI admission."""
    if not SHA.fullmatch(sha):
        raise GateError("Invalid Chronicles source SHA")
    url = ORIGIN + "/release.json?receipt_check=" + str(time.time_ns())
    try:
        manifest = public(url)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False
    return isinstance(manifest, dict) and manifest.get("build") == sha


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--live-only":
        try:
            matches = live_matches(sys.argv[2])
        except GateError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(("CHRONICLES_PAGES_SHA_ALREADY_LIVE" if matches else
               "CHRONICLES_PAGES_NEEDS_PUBLISH") + " sha=" + sys.argv[2])
        return 0 if matches else 1
    if len(sys.argv) != 2:
        return 64
    try:
        if verified_live(sys.argv[1], os.environ.get("GH_TOKEN", "")):
            print("CHRONICLES_PAGES_ALREADY_VERIFIED sha=" + sys.argv[1])
            return 0
        print("CHRONICLES_PAGES_RECEIPT_MISSING_OR_LIVE_DRIFT sha=" + sys.argv[1])
        return 1
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
