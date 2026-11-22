#!/usr/bin/env python3
"""Read-only public R2 cutover proof for Chronicles' four inherited media files.

Only the exact SHA-256 and size pins from the Chronicles source manifest are
accepted. This probe NEVER publishes, deletes or activates an asset URL.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

HOST = "assets.chronicles.shadowops.dpdns.org"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
MAX_OBJECT_BYTES = 6_000_000


@dataclass(frozen=True)
class Asset:
    name: str
    key: str
    size: int
    sha256: str
    mime: str
    versioned: bool


# Identical to the four pins in Chronicles' current frontend R2 manifest.
PINS = (
    Asset("first-verse", "chronicles/music/Chronicles of matthias - First verse.mp3",
          4871666, "5e545865cf16504e93482d380ead4c33dd77b794e85d7ee5afb400d3d0fbe2c5",
          "audio/mpeg", False),
    Asset("second-verse", "chronicles/music/Chronicles of matthias - Second verse.mp3",
          4997378, "1f55001289415bfe1c6b01b7d1d73b8d963b0dbbadc90b07505efa2ffa263af4",
          "audio/mpeg", False),
    Asset("party-master", "chronicles/tactics/party/master/chronicles-tactics-party-2f6ef378ef7ea982.blend",
          501446, "2f6ef378ef7ea9823d70bdf289fa05c0656448e0cc3802b3aeb3679353d54e48",
          "application/octet-stream", True),
    Asset("party-runtime", "chronicles/tactics/party/runtime/chronicles-tactics-party-0d12bb3c3ec92d55.glb",
          2423220, "0d12bb3c3ec92d55b3e4af7b64cade1dede55537ff118c360ec260f788ff640c",
          "model/gltf-binary", True),
)


class ProbeError(ValueError):
    """Public proof failed: never authorize a manifest cutover."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method: str, asset: Asset) -> tuple[int, dict[str, str], bytes]:
    if method not in ("HEAD", "GET") or asset not in PINS:
        raise ProbeError("unexpected request")
    key = urllib.parse.quote(asset.key, safe="/-._~")
    req = urllib.request.Request(
        f"https://{HOST}/{key}", method=method,
        headers={"Origin": ORIGIN, "User-Agent": "shadowops-chronicles-media-proof/1"},
    )
    try:
        with urllib.request.build_opener(_NoRedirects).open(req, timeout=20) as response:
            body = response.read(asset.size + 1) if method == "GET" else b""
            return response.status, {k.lower(): v for k, v in response.headers.items()}, body
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"{asset.name}: {method} HTTP {exc.code}") from None


def _max_age(directives: list[str]) -> int:
    values = [d.split("=", 1)[1].strip().strip('"')
              for d in directives if d.startswith("max-age=")]
    if len(values) != 1 or not values[0].isdigit():
        raise ProbeError("missing or ambiguous cache max-age")
    return int(values[0])


def validate(status: int, headers: dict[str, str], asset: Asset,
             body: bytes | None = None) -> None:
    if status != 200:
        raise ProbeError(f"{asset.name}: HTTP status is not 200")
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != asset.mime:
        raise ProbeError(f"{asset.name}: incorrect content-type")
    if headers.get("access-control-allow-origin") not in ("*", ORIGIN):
        raise ProbeError(f"{asset.name}: staging CORS is not allowed")
    directives = [d.strip().lower() for d in headers.get("cache-control", "").split(",")]
    if "public" not in directives or "private" in directives or "no-store" in directives:
        raise ProbeError(f"{asset.name}: invalid public cache policy")
    age = _max_age(directives)
    if asset.versioned:
        if "immutable" not in directives or age != 31536000:
            raise ProbeError(f"{asset.name}: versioned object cache policy differs")
    elif "immutable" in directives or age > 86400:
        raise ProbeError(f"{asset.name}: mutable filename has unsafe cache policy")
    length = headers.get("content-length")
    if length is not None and (not length.isdecimal() or int(length) != asset.size):
        raise ProbeError(f"{asset.name}: incorrect content-length")
    if body is not None:
        if len(body) != asset.size:
            raise ProbeError(f"{asset.name}: incorrect body size")
        if hashlib.sha256(body).hexdigest() != asset.sha256:
            raise ProbeError(f"{asset.name}: SHA-256 mismatch")


Transport = Callable[[str, Asset], tuple[int, dict[str, str], bytes]]


def probe(fetch: Transport = request) -> dict[str, int | str]:
    if len(PINS) != 4 or len({p.key for p in PINS}) != 4:
        raise ProbeError("asset pin inventory is not exactly four unique keys")
    total = 0
    for asset in PINS:
        if not 1 <= asset.size <= MAX_OBJECT_BYTES or not re.fullmatch("[0-9a-f]{64}", asset.sha256):
            raise ProbeError("invalid media pin")
        status, headers, _ = fetch("HEAD", asset)
        validate(status, headers, asset)
        status, headers, body = fetch("GET", asset)
        validate(status, headers, asset, body)
        total += len(body)
    return {"status": "ready-for-manual-review", "assets": len(PINS), "bytes": total}


def main() -> int:
    try:
        result = probe()
    except (ProbeError, urllib.error.URLError, TimeoutError, OSError) as exc:
        print("CHRONICLES_MEDIA_R2_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    print("CHRONICLES_MEDIA_R2_PROOF " +
          " ".join(f"{key}={value}" for key, value in sorted(result.items())))
    print("Cutover is NOT authorized by a public probe alone.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
