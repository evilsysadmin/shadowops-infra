#!/usr/bin/env python3
"""Bounded, source-accredited, manual publication of approved Football WebP atlases.

Only ShadowOps Infra owns the credential. Importing or running "validate" makes
no network calls and never changes R2. Publishing requires admitted Football
main CI, capacity checks, and immutable/public byte verification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import sys
import urllib.parse
import urllib.request
import zipfile

import football_delivery as delivery
import football_pages as pages

SOURCE = "evilsysadmin/football-of-matthias"
ARTIFACT = "football-r2-atlas-candidates"
PREFIX = "football/atlases/v1/"
PUBLIC = "https://assets.chess-studio.shadowops.dpdns.org/"
ORIGIN = "https://staging.football.shadowops.dpdns.org"
TEAMS = {"fc_matthias", "real_enroque"}
FAMILIES = {"lateral_run": 1, "directional_run": 4, "goalkeeper_run": 4}
MAX_UNCOMPRESSED = 4_194_304
EXPECTED_FILES = {
    f"{team}_{family}_v1.webp"
    for team in TEAMS for family in FAMILIES
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_pack(payload: bytes) -> dict[str, bytes]:
    if not payload or len(payload) > MAX_UNCOMPRESSED:
        raise delivery.DeliveryError("Atlas archive exceeds bounded limit")
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != 7 or len(set(names)) != 7:
                raise delivery.DeliveryError("Exactly six WebP sheets and one manifest required")
            if set(names) != EXPECTED_FILES | {"atlas-manifest-v1.json"}:
                raise delivery.DeliveryError("Unexpected file in source atlas artifact")
            if sum(e.file_size for e in entries) > MAX_UNCOMPRESSED:
                raise delivery.DeliveryError("Atlas archive uncompressed budget exceeded")
            for entry in entries:
                name = entry.filename
                if (entry.is_dir() or entry.flag_bits & 1
                        or entry.file_size > MAX_UNCOMPRESSED
                        or (entry.external_attr >> 16) & 0o170000 == 0o120000
                        or str(PurePosixPath(name)) != name):
                    raise delivery.DeliveryError("Unsafe atlas archive entry")
            manifest = json.loads(archive.read("atlas-manifest-v1.json"))
            if not isinstance(manifest, dict):
                raise delivery.DeliveryError("Atlas manifest must be an object")
            if (manifest.get("schema") != 1 or manifest.get("codec") != "webp-lossless"
                    or manifest.get("cell") != {"width": 128, "height": 144}):
                raise delivery.DeliveryError("Unexpected atlas manifest contract")
            rows = manifest.get("assets")
            if not isinstance(rows, list) or len(rows) != 6:
                raise delivery.DeliveryError("Six exact atlas records required")
            result = {}
            for item in rows:
                if not isinstance(item, dict):
                    raise delivery.DeliveryError("Atlas item must be an object")
                team, family, name = item.get("team"), item.get("family"), item.get("file")
                if (team not in TEAMS or family not in FAMILIES
                        or name != f"{team}_{family}_v1.webp" or name in result
                        or item.get("columns") != 8 or item.get("rows") != FAMILIES[family]):
                    raise delivery.DeliveryError("Atlas family/team/layout mismatch")
                data = archive.read(name)
                if (len(data) != item.get("bytes") or len(data) > 1_048_576
                        or data[:4] != b"RIFF" or data[8:12] != b"WEBP"
                        or sha256(data) != item.get("sha256")):
                    raise delivery.DeliveryError("Atlas WebP bytes/hash mismatch")
                result[name] = data
            if set(result) != EXPECTED_FILES:
                raise delivery.DeliveryError("Incomplete atlas family matrix")
            return result
    except (zipfile.BadZipFile, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise delivery.DeliveryError("Malformed Football atlas ZIP/manifest") from exc


def admitted_source(source_sha: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{40}", source_sha):
        raise delivery.DeliveryError("Exact full source SHA required")
    admitted = delivery.admit()
    if admitted is None or admitted["source_sha"] != source_sha:
        raise delivery.DeliveryError("Football main CI not accredited for exact SHA")
    artifacts = delivery.github(f"/repos/{SOURCE}/actions/runs/{admitted['run_id']}/artifacts?per_page=100")
    candidates = [x for x in artifacts.get("artifacts", [])
                  if x.get("name") == ARTIFACT and x.get("expired") is False]
    if len(candidates) != 1:
        raise delivery.DeliveryError("Unique live R2 candidate artifact required")
    item = candidates[0]
    if (item.get("workflow_run", {}).get("head_sha") != source_sha
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("digest", ""))):
        raise delivery.DeliveryError("Atlas artifact lacks exact source/digest provenance")
    return {"artifact_id": item["id"], "artifact_digest": item["digest"], "source_sha": source_sha}


def public_bytes(name: str) -> bytes:
    uri = PUBLIC + PREFIX + name
    request = urllib.request.Request(uri, headers={"Origin": ORIGIN, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=25) as response:
        if response.status != 200:
            raise delivery.DeliveryError("Public atlas status is not 200")
        cors = response.headers.get("Access-Control-Allow-Origin", "")
        if cors not in ("*", ORIGIN):
            raise delivery.DeliveryError("Public atlas lacks staging CORS")
        if "immutable" not in response.headers.get("Cache-Control", "").lower():
            raise delivery.DeliveryError("Public atlas missing immutable Cache-Control")
        return response.read(1_048_577)


def verify_public(pack: dict[str, bytes], names: set[str] | None = None) -> None:
    for name in sorted(pack if names is None else names):
        try:
            actual = public_bytes(name)
        except (OSError, ValueError) as exc:
            raise delivery.DeliveryError("Public atlas/CDN verification failed") from exc
        if sha256(actual) != sha256(pack[name]):
            raise delivery.DeliveryError("Public WebP bytes differ from approved source")
    print("FOOTBALL_ATLAS_PUBLIC_CORS_AND_SHA_OK sheets=" + str(len(pack if names is None else names)))


def publish(pack: dict[str, bytes], source_sha: str) -> None:
    admitted_source(source_sha)
    account = pages.required("CLOUDFLARE_ACCOUNT_ID")
    if not re.fullmatch(r"[a-f0-9]{32}", account):
        raise delivery.DeliveryError("Exact Cloudflare account identity required")
    current = delivery.inventory(account)
    # Never overwrite an existing versioned key. Verify its public bytes instead.
    existing = {name for name in pack if PREFIX + name in current}
    additions = {PREFIX + name: len(payload) for name, payload in pack.items() if name not in existing}
    delivery.budget(current, additions)  # Shared free-tier headroom before first write
    # football_delivery.budget tracks its Pages runtime prefix; account also
    # for these separate shared CDN atlas keys in Football's 512 MiB budget.
    atlas_used = sum(size for key, size in current.items() if key.startswith("football/"))
    if atlas_used + sum(additions.values()) > delivery.FOOTBALL_BUDGET:
        raise delivery.DeliveryError("Football atlas free-tier allocation exhausted")
    if existing:
        verify_public(pack, existing)
    # Recheck the original main/CI provenance just before any mutation.
    admitted_source(source_sha)
    for name in sorted(pack):
        if name in existing:
            continue
        uri = (f"/accounts/{account}/r2/buckets/{delivery.BUCKET}/objects/"
               + urllib.parse.quote(PREFIX + name, safe="/-._~"))
        delivery.r2_request("PUT", uri, data=pack[name], content_type="image/webp")
    verify_public(pack)
    print(f"FOOTBALL_ATLAS_R2_PUBLISHED source_sha={source_sha} sheets=6")


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in ("validate", "publish"):
        raise delivery.DeliveryError("Usage: football_atlas_publication.py validate|publish ZIP SHA")
    action, archive, sha = sys.argv[1:]
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise delivery.DeliveryError("Full source SHA required")
    from pathlib import Path
    pack = validate_pack(Path(archive).read_bytes())
    print("FOOTBALL_ATLAS_PACK_VERIFIED sheets=6")
    if action == "publish":
        publish(pack, sha)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (delivery.DeliveryError, FileNotFoundError) as exc:
        print("FOOTBALL_ATLAS_PUBLICATION_BLOCKED " + str(exc), file=sys.stderr)
        raise SystemExit(1)
