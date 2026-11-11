#!/usr/bin/env python3
"""Assemble immutable, Identity-protected Snooker Pages bytes from admitted CI ZIP.

No rebuild, no external asset or worker from Snooker, and no Cloudflare writes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

import snooker_source_admission as source

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "edge" / "snooker-identity-gate.mjs"
AUTH = {"provider": "shadowops-id", "audience": "snooker", "required": True}
HEX = re.compile(r"[a-f0-9]{40}\Z")
MAX_BYTES = 50 * 1024 * 1024

class PackageError(ValueError):
    pass

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def prepare(zip_path: Path, zip_digest: str, sha: str, dest: Path) -> dict:
    if not HEX.fullmatch(sha):
        raise PackageError("Full immutable source SHA required")
    try:
        source.verify_archive(zip_path, zip_digest)
    except source.AdmissionError as exc:
        raise PackageError("Unverified source artifact: " + str(exc)) from None
    # The source build identifies its immutable *running* SHA so clients can
    # compare it to protected /release.json and notify about new versions.
    # Reject mismatched/legacy bundles *before* creating any output directory.
    with zipfile.ZipFile(zip_path) as candidate:
        scripts = [item for item in candidate.infolist()
                   if item.filename.startswith("assets/") and item.filename.endswith(".js")]
        if not scripts or not any(sha.encode("ascii") in candidate.read(item) for item in scripts):
            raise PackageError("Published JS bundle does not embed the admitted source SHA")
    if dest.exists() or dest.is_symlink():
        raise PackageError("Output directory already exists; cannot reuse stale release")
    edge = EDGE.read_bytes()
    if len(edge) > 500_000 or b"SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL" not in edge:
        raise PackageError("Expected audited Snooker edge binding missing")
    if b"if(url.hostname!==HOST)" not in edge:
        raise PackageError("Pages aliases must be blocked by the trusted Worker")
    # validate_archive has already bounded every entry and its CRC; extract only
    # original Vite bytes. The source ZIP may not supply _worker.js or release.json.
    manifest = {}
    dest.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(zip_path) as archive:
        for item in archive.infolist():
            file = dest / item.filename
            file.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(item)
            file.write_bytes(data)
            manifest[item.filename] = {"sha256": digest(data), "bytes": len(data)}
    (dest / "_worker.js").write_bytes(edge)
    manifest["_worker.js"] = {"sha256": digest(edge), "bytes": len(edge)}
    metadata = {
        "schema": 1,
        "application": "snooker-of-matthias",
        "environment": "staging",
        "source_sha": sha,
        "source_artifact_digest": zip_digest,
        "authentication": AUTH,
        "files": dict(sorted(manifest.items())),
    }
    (dest / "release.json").write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    verify(dest, sha, zip_digest)
    return metadata

def verify(root: Path, sha: str, zip_digest: str) -> dict:
    if not HEX.fullmatch(sha) or not source.DIGEST.fullmatch(zip_digest):
        raise PackageError("Invalid pinned source digest or SHA")
    try:
        value = json.loads((root / "release.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise PackageError("Invalid release manifest") from None
    if (not isinstance(value, dict)
        or value.get("schema") != 1
        or value.get("application") != "snooker-of-matthias"
        or value.get("environment") != "staging"
        or value.get("source_sha") != sha
        or value.get("source_artifact_digest") != zip_digest
        or value.get("authentication") != AUTH):
        raise PackageError("Wrong release identity or authentication")
    expected = value.get("files")
    if not isinstance(expected, dict) or len(expected) < 3:
        raise PackageError("Release manifest lacks runtime/worker entries")
    actual = {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    }
    if actual != set(expected) | {"release.json"} or any(p.is_symlink() for p in root.rglob("*")):
        raise PackageError("Unexpected or missing release files")
    if "_worker.js" not in expected or "index.html" not in expected or not any(
        name.startswith("assets/") and name.endswith(".js") for name in expected
    ):
        raise PackageError("Missing audited Worker or Vite runtime")
    total = 0
    for name, row in expected.items():
        p = Path(name)
        if p.is_absolute() or ".." in p.parts or not isinstance(row, dict):
            raise PackageError("Invalid manifest path")
        data = (root / p).read_bytes()
        total += len(data)
        if row != {"sha256": digest(data), "bytes": len(data)} or len(data) > 25 * 1024 * 1024:
            raise PackageError("Release bytes differ from manifest")
    if total > MAX_BYTES:
        raise PackageError("Release total exceeds budget")
    # A correct manifest is not enough when the *runtime JavaScript* was built
    # for another source revision. Prove alignment again before Wrangler upload.
    scripts = [root / name for name in expected
               if name.startswith("assets/") and name.endswith(".js")]
    if not scripts or not any(sha.encode("ascii") in script.read_bytes() for script in scripts):
        raise PackageError("Release runtime SHA differs from signed release metadata")
    if expected["_worker.js"]["sha256"] != digest(EDGE.read_bytes()):
        raise PackageError("Worker differs from reviewed Infra source")
    return value

def main(argv: list[str]) -> int:
    try:
        if len(argv) == 6 and argv[1] == "prepare":
            result = prepare(Path(argv[2]), argv[3], argv[4], Path(argv[5]))
            print("SNOOKER_RELEASE_PREPARED sha=" + result["source_sha"] +
                  " artifact_digest=" + result["source_artifact_digest"] +
                  " files=" + str(len(result["files"])))
        elif len(argv) == 5 and argv[1] == "verify":
            result = verify(Path(argv[2]), argv[3], argv[4])
            print("SNOOKER_RELEASE_VERIFIED sha=" + result["source_sha"] +
                  " files=" + str(len(result["files"])))
        else:
            raise PackageError("Usage: prepare ZIP digest SHA OUTPUT | verify FOLDER SHA digest")
        return 0
    except (OSError, PackageError) as exc:
        print("SNOOKER_RELEASE_BLOCKED " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
