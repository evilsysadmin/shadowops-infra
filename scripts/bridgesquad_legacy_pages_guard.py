#!/usr/bin/env python3
"""Read-only guard against an old unprotected GitHub Pages copy of Bridge Squad.

Public Pages is an authentication bypass even when the new Cloudflare domain
is perfectly guarded. Unknown HTTP/network state is a denial, not success.
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

import bridgesquad_source_admission as source

API = "https://api.github.com/repos/" + source.SOURCE + "/pages"
PUBLIC = "https://evilsysadmin.github.io/matthias-bridge-squad"
ROUTES = (PUBLIC + "/", PUBLIC + "/index.html")
MAX = 8192


class Refused(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read(url: str, *, token: str = "") -> tuple[int, bytes]:
    if url not in (API, *ROUTES):
        raise Refused("unapproved legacy URL")
    if url == API and not token:
        raise Refused("GitHub release read credential missing")
    headers = {"Accept": "application/vnd.github+json" if url == API else "text/html",
               "User-Agent": "ShadowOps-BridgeSquad-Legacy-Denial/1.0"}
    if url == API:
        headers["Authorization"] = "Bearer " + token
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=12) as response:
            return response.status, response.read(MAX + 1)
    except urllib.error.HTTPError as error:
        return error.code, error.read(MAX + 1)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Refused("legacy Pages HTTP cannot be verified") from None


def inspect(*, pages=None, public=None) -> dict:
    if pages is None:
        pages = lambda: _read(API, token=os.environ.get("GH_TOKEN", ""))
    if public is None:
        public = lambda url: _read(url)
    status, body = pages()
    # Explicit Pages REST 404 is the authoritative disablement receipt.
    if status != 404 or not isinstance(body, bytes) or len(body) > MAX:
        raise Refused("GitHub Pages configuration is not proven disabled")
    for url in ROUTES:
        status, body = public(url)
        if status != 404 or not isinstance(body, bytes) or len(body) > MAX:
            raise Refused("Legacy public GitHub Pages origin still accessible")
        if any(marker in body.lower() for marker in
               (b"<canvas", b"<title>matthias bridge squad", b"shadowops.mbs.")):
            raise Refused("Protected game content leaked under legacy 404")
    return {"legacy_github_pages": "disabled", "legacy_http": "404-only"}


def main(argv: list[str]) -> int:
    if argv != ["inspect"]:
        print("Usage: bridgesquad_legacy_pages_guard.py inspect", file=sys.stderr)
        return 2
    try:
        receipt = inspect()
    except (Refused, ValueError, OSError):
        print("BRIDGESQUAD_LEGACY_PAGES_REFUSED", file=sys.stderr)
        return 1
    print("BRIDGESQUAD_LEGACY_PAGES_OK " +
          " ".join(f"{key}={value}" for key, value in receipt.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
