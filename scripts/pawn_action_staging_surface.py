#!/usr/bin/env python3
"""Read-only anonymous probe of the *locked* Pawn Action staging edge.

No Cloudflare API token, browser cookie, JWT, R2 binding or publication.
The probe must FAIL once staging becomes playable; it certifies only the
pre-activation holding state, never authenticated gameplay.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

HOST = "staging.pawnaction.shadowops.dpdns.org"
BASE = "https://" + HOST
STATUS = "/_shadowops/status"
# Every file recognized by the private-delivery Worker's FILES allowlist
# must be denied while the holding edge is locked. The offline contract
# test reads that Worker allowlist to detect newly introduced files.
DENIED = (
    "/",
    "/index.html",
    "/index.js",
    "/index.wasm",
    "/index.pck",
    "/index.png",
    "/index.icon.png",
    "/index.apple-touch-icon.png",
    "/index.audio.worklet.js",
    "/index.audio.position.worklet.js",
    "/_shadowops/session.js",
    "/api/pawn-action/session",
    "/release.json",
    "/pawn-action/current.json",
    "/pawn-slug-godot/current.json",
    "/pawn-action/releases/0000000000000000/index.wasm",
)
BODY_LIMIT = 4096


class SurfaceBlocked(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never follow a redirect to a public CDN or to an IdP.
        return None


def fetch(path: str, method: str):
    if path not in (STATUS, *DENIED) or method not in ("GET", "HEAD"):
        raise SurfaceBlocked("Unexpected public probe target")
    request = urllib.request.Request(BASE + path, method=method,
                                     headers={"Accept": "application/json, text/html"})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=8)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            code = response.status
            headers = dict(response.headers.items())
            # The probe never downloads large game assets; only a tiny response
            # prefix for the locked status endpoint.
            body = response.read(BODY_LIMIT + 1) if path == STATUS and method == "GET" else b""
            return code, headers, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SurfaceBlocked("Staging HTTPS endpoint not verifiably reachable: "
                             + type(exc).__name__) from None


def inspect(request=fetch):
    checks = {}
    for path, method in ((STATUS, "GET"), ("/", "GET"), ("/", "HEAD"),
                         *((p, method) for p in DENIED if p != "/"
                           for method in ("HEAD", "GET"))):
        code, headers, body = request(path, method)
        if type(code) is not int or not isinstance(headers, dict) or not isinstance(body, bytes):
            raise SurfaceBlocked("Malformed staging HTTP response")
        lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if ("no-store" not in lower.get("cache-control", "")
                or lower.get("x-content-type-options") != "nosniff"
                or "location" in lower or 300 <= code < 400):
            raise SurfaceBlocked("Staging response redirects, caches or lacks security headers")
        if path == STATUS:
            if code != 200 or "application/json" not in lower.get("content-type", "") or len(body) > BODY_LIMIT:
                raise SurfaceBlocked("Locked staging status unavailable")
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeError):
                raise SurfaceBlocked("Locked staging status malformed") from None
            if payload != {"application": "pawn-action", "environment": "staging",
                           "state": "locked", "game_ready": False}:
                raise SurfaceBlocked("Staging not in verified locked state")
        elif code not in (403, 404, 503):
            raise SurfaceBlocked("Staging exposes a game file or public page: " + path)
        checks[method + " " + path] = code
    return {"host": HOST, "state": "locked", "gameReady": False,
            "publicChecks": checks, "published": False}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args != ["probe"]:
        print("Usage: pawn_action_staging_surface.py probe", file=sys.stderr)
        return 2
    try:
        result = inspect()
    except SurfaceBlocked as exc:
        print("PAWN_ACTION_LOCKED_SURFACE_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print("PAWN_ACTION_LOCKED_SURFACE_VERIFIED " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
