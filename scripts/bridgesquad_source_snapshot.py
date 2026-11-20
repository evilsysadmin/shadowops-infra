#!/usr/bin/env python3
"""Rebuild a private Bridge Squad source archive from a pinned public Git commit.

The game repository is public, but its Actions artifact download requires an
Actions token scoped to THAT repository. Infra's GITHUB_TOKEN is not that
token. Keep the existing exact-main green CI/artifact provenance admission,
then fetch only the byte-exact public index.html at its immutable commit SHA.
Build the two-file archive independently in Infra; never run game-owned code
or make the protected game publicly accessible through a hosting alias.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request
import zipfile

import bridgesquad_source_admission as source

RAW = "https://raw.githubusercontent.com/" + source.SOURCE + "/"
FILE = "/index.html"


class Refused(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_html(sha: str, data: bytes) -> None:
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise Refused("exact source commit SHA required")
    if not isinstance(data, bytes) or not 64 <= len(data) <= source.MAX_HTML:
        raise Refused("source HTML missing or oversized")
    try:
        document = data.decode("utf-8")
    except UnicodeError:
        raise Refused("source HTML must be UTF-8") from None
    if not document.lstrip().lower().startswith("<!doctype html>") or (
        "<title>Matthias Bridge Squad" not in document
    ):
        raise Refused("unrecognized Bridge Squad HTML")


def download(sha: str, *, opener=None) -> bytes:
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise Refused("invalid pinned source SHA")
    url = RAW + sha + FILE
    req = urllib.request.Request(url, headers={
        "Accept": "text/plain",
        "User-Agent": "ShadowOps-BridgeSquad-SHA-Snapshot/1.0",
    })
    client = opener if opener is not None else urllib.request.build_opener(NoRedirect())
    try:
        with client.open(req, timeout=15) as response:
            if response.status != 200 or response.geturl() != url:
                raise Refused("source redirect or non-200 refused")
            data = response.read(source.MAX_HTML + 1)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Refused("immutable source unavailable") from None
    validate_html(sha, data)
    return data


def archive_bytes(sha: str, html: bytes) -> bytes:
    validate_html(sha, html)
    manifest = {
        "schema": 1,
        "application": "matthias-bridge-squad",
        "environment": "production",
        "source_repository": source.SOURCE,
        "source_sha": sha,
        "authentication": {
            "provider": "shadowops-id", "audience": "bridgesquad",
            "required": True,
        },
        "files": {"index.html": {
            "sha256": hashlib.sha256(html).hexdigest(), "bytes": len(html),
        }},
    }
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.html", html)
        archive.writestr("release.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    result = data.getvalue()
    if len(result) > source.MAX_ZIP:
        raise Refused("source snapshot ZIP exceeds admission limit")
    return result


def snapshot(sha: str, output: Path, *, fetch=download) -> dict:
    """No mutation except creating this ONE new local private archive."""
    if output.is_symlink() or output.exists() or not output.parent.is_dir():
        raise Refused("output must be a new file in an existing directory")
    html = fetch(sha)
    data = archive_bytes(sha, html)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    # The ZIP digest below describes the independently rebuilt private ZIP,
    # not the separate proof-of-CI-upload artifact's digest.
    try:
        output.write_bytes(data)
        receipt = source.verify_archive(output, digest, sha)
    except (OSError, source.AdmissionError):
        output.unlink(missing_ok=True)
        raise Refused("source snapshot verification failed") from None
    return {**receipt, "snapshot_digest": digest}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "snapshot":
        print("Usage: bridgesquad_source_snapshot.py snapshot SOURCE_SHA OUTPUT_ZIP",
              file=sys.stderr)
        return 2
    try:
        receipt = snapshot(argv[1], Path(argv[2]))
    except (Refused, ValueError, OSError):
        print("BRIDGESQUAD_SOURCE_SNAPSHOT_REFUSED", file=sys.stderr)
        return 1
    print("snapshot_digest=" + receipt["snapshot_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
