#!/usr/bin/env python3
"""Read-only public CDN contract for one pinned Chronicles R2 object.

This is only the public edge check. It does not replace the legacy private
Cloudflare bucket/domain inventory until ownership is separately transferred.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.error
import urllib.request
from typing import Callable

HOST = "assets.chronicles.shadowops.dpdns.org"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
MUTABLE_KEY = "sprites/ash-goblin.webp"
IMMUTABLE_KEY = "sprites/ash-goblin-96ed70aafe94827f.webp"
IMMUTABLE_SHA256 = "96ed70aafe94827f3663228896af612055c9abf12b441a78f7bb4c1fa3b17656"
IMMUTABLE_SIZE = 122882
IMMUTABLE_MAX_AGE = 31536000
Headers = dict[str, str]
Transport = Callable[[str, str], tuple[int, Headers, bytes]]


class ProbeError(Exception):
    """Fail-closed public object contract violation."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method: str, key: str) -> tuple[int, Headers, bytes]:
    # Fixed HTTPS host and fixed keys: no user-supplied URLs, redirects, tokens,
    # Cloudflare APIs or bucket enumeration. Body is bounded to pinned size + 1.
    if method not in {"HEAD", "GET"} or key not in {MUTABLE_KEY, IMMUTABLE_KEY}:
        raise ProbeError("unexpected HTTP request")
    req = urllib.request.Request(
        f"https://{HOST}/{key}", method=method,
        headers={"Origin": ORIGIN, "User-Agent": "shadowops-chronicles-edge-probe/1"},
    )
    opener = urllib.request.build_opener(_NoRedirects)
    try:
        with opener.open(req, timeout=15) as response:
            body = response.read(IMMUTABLE_SIZE + 1) if method == "GET" else b""
            return response.status, {k.lower(): v for k, v in response.headers.items()}, body
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"{method} returned HTTP {exc.code}") from None


def _directives(headers: Headers) -> list[str]:
    return [token.strip().lower() for token in headers.get("cache-control", "").split(",")]


def _headers_ok(headers: Headers) -> None:
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "image/webp":
        raise ProbeError("content-type is not image/webp")
    if headers.get("access-control-allow-origin") not in ("*", ORIGIN):
        raise ProbeError("CORS excludes Chronicles staging origin")


def _max_age(directives: list[str]) -> list[int]:
    ages = [value.split("=", 1)[1].strip().strip('"') for value in directives if value.startswith("max-age=")]
    if any(not age.isdigit() for age in ages):
        raise ProbeError("invalid max-age")
    return [int(age) for age in ages]


def probe(fetch: Transport = request) -> dict[str, str]:
    status, headers, _ = fetch("HEAD", MUTABLE_KEY)
    if status != 200:
        raise ProbeError("mutable HEAD did not return 200")
    _headers_ok(headers)
    mutable_cache = _directives(headers)
    if "immutable" in mutable_cache or any(age >= IMMUTABLE_MAX_AGE for age in _max_age(mutable_cache)):
        raise ProbeError("mutable alias has unsafe long-lived browser cache")

    status, headers, _ = fetch("HEAD", IMMUTABLE_KEY)
    if status != 200:
        raise ProbeError("immutable HEAD did not return 200")
    _headers_ok(headers)
    cache = _directives(headers)
    if "public" not in cache or "immutable" not in cache or _max_age(cache) != [IMMUTABLE_MAX_AGE]:
        raise ProbeError("immutable object has incorrect public browser cache policy")
    length = headers.get("content-length")
    if length is not None and length != str(IMMUTABLE_SIZE):
        raise ProbeError("immutable HEAD size mismatch")

    status, headers, data = fetch("GET", IMMUTABLE_KEY)
    if status != 200:
        raise ProbeError("immutable GET did not return 200")
    _headers_ok(headers)
    if len(data) != IMMUTABLE_SIZE:
        raise ProbeError("immutable public byte count mismatch")
    if hashlib.sha256(data).hexdigest() != IMMUTABLE_SHA256:
        raise ProbeError("immutable public SHA-256 mismatch")
    return {"edge": "ok", "immutable_sha256": IMMUTABLE_SHA256, "bytes": str(len(data))}


def main() -> int:
    try:
        result = probe()
    except (ProbeError, urllib.error.URLError, TimeoutError, OSError) as exc:
        print("CHRONICLES_R2_EDGE_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    print("CHRONICLES_R2_EDGE_OK " + " ".join(f"{k}={v}" for k, v in sorted(result.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
