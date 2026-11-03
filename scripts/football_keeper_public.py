#!/usr/bin/env python3
"""Read-only keeper R2 attestation before publishing a Football staging release.

The manifest is fetched by Infra from the exact admitted source commit. This
script never owns Cloudflare credentials and never mutates either R2 bucket.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

STAGING_ORIGIN = "https://staging.football.shadowops.dpdns.org"
PUBLIC_BASE = "https://pub-cda6a24cd2f94f7eaaf4d112351bf526.r2.dev/atlases/v1"
MAX_WEBP_BYTES = 4 * 1024 * 1024
FILENAMES = {
    "fc_matthias": "fc_matthias_keeper_catch_v1.webp",
    "real_enroque": "real_enroque_keeper_catch_v1.webp",
}


class KeeperR2Error(ValueError):
    pass


def verify_manifest(meta: dict, *, opener=urllib.request.urlopen) -> bool:
    if not isinstance(meta, dict) or meta.get("version") != 1:
        raise KeeperR2Error("Invalid keeper manifest version")
    if meta.get("enabled") is not True:
        if meta.get("enabled") is not False:
            raise KeeperR2Error("Keeper enabled flag must be boolean")
        print("FOOTBALL_KEEPER_R2_STAGING_DISABLED")
        return False
    if (meta.get("bucket") != "football" or meta.get("prefix") != "atlases/v1/"
            or meta.get("quality_contract") != "football-keeper-catch-v1"
            or meta.get("cdn_base") != PUBLIC_BASE):
        raise KeeperR2Error("Unexpected dedicated R2 bucket, origin or atlas contract")
    if meta.get("cell") != {"width": 128, "height": 144} or meta.get("columns") != 8 or meta.get("rows") != 1:
        raise KeeperR2Error("Invalid keeper atlas dimensions")

    entries = meta.get("entries")
    if not isinstance(entries, list) or len(entries) != 2:
        raise KeeperR2Error("Expected exactly two original keeper atlases")
    # Reject duplicate/missing teams before initiating any remote request.
    teams = [entry.get("team") if isinstance(entry, dict) else None for entry in entries]
    if set(teams) != set(FILENAMES) or len(set(teams)) != len(teams):
        raise KeeperR2Error("Duplicated or missing keeper team")
    remaining = dict(FILENAMES)
    for entry in entries:
        if not isinstance(entry, dict):
            raise KeeperR2Error("Malformed keeper atlas entry")
        team = entry.get("team")
        if team not in remaining or entry.get("file") != remaining[team]:
            raise KeeperR2Error("Unexpected or duplicated keeper atlas file")
        name = remaining.pop(team)
        sha = entry.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise KeeperR2Error("Missing pinned keeper SHA-256")

        url = PUBLIC_BASE + "/" + name
        request = urllib.request.Request(url, headers={
            "Origin": STAGING_ORIGIN,
            "User-Agent": "ShadowOps-Football-Keeper-R2-Preflight/1.0",
            "Cache-Control": "no-cache",
        })
        try:
            with opener(request, timeout=18) as response:
                status = response.status
                final_url = response.geturl()
                content_type = response.headers.get_content_type()
                cors = response.headers.get("Access-Control-Allow-Origin", "")
                raw = response.read(MAX_WEBP_BYTES + 1)
        except (OSError, TimeoutError) as exc:
            raise KeeperR2Error("Public keeper R2 WebP request failed: " + name) from exc
        if status != 200 or final_url != url or content_type != "image/webp":
            raise KeeperR2Error("Unexpected public keeper HTTP response: " + name)
        if cors not in ("*", STAGING_ORIGIN):
            raise KeeperR2Error("Staging origin is not permitted by keeper R2 CORS: " + name)
        if not 0 < len(raw) <= MAX_WEBP_BYTES or raw[:4] != b"RIFF" or raw[8:12] != b"WEBP":
            raise KeeperR2Error("Keeper payload is not a bounded WebP: " + name)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise KeeperR2Error("Keeper public bytes differ from source SHA-256: " + name)
        print("FOOTBALL_KEEPER_R2_OBJECT_VERIFIED team=" + team
              + " bytes=" + str(len(raw)) + " sha256=" + sha)
    if remaining:
        raise KeeperR2Error("Missing keeper team")
    print("FOOTBALL_KEEPER_R2_STAGING_VERIFIED origin=" + STAGING_ORIGIN)
    return True


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise KeeperR2Error("Usage: football_keeper_public.py source-keeper-manifest.json")
        verify_manifest(json.loads(Path(sys.argv[1]).read_text()))
    except (KeeperR2Error, ValueError, OSError) as exc:
        print("FOOTBALL_KEEPER_R2_STAGING_BLOCKED " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
