#!/usr/bin/env python3
"""Prepare a reproducible, OFFLINE Pawn Action R2 Web release candidate.

Consumes an exact GitHub Actions ZIP + externally admitted source receipt.
No Cloudflare API calls, DNS changes, Pages uploads or mutable pointer writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

from pawn_action_source_admission import AdmissionError, SHA, verify_archive

ORIGIN = "https://assets.chess-studio.shadowops.dpdns.org"
PREFIX = "pawn-action"
PAGES_FILE_LIMIT = 25 * 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".wasm": "application/wasm",
    ".pck": "application/octet-stream",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _render(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _build_manifest(contents: dict[str, bytes], source_sha: str, artifact_digest: str,
                    run_id: int, artifact_id: int) -> dict:
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise AdmissionError("Exact Pawn Action source SHA required")
    if not isinstance(artifact_digest, str) or not artifact_digest.startswith("sha256:"):
        raise AdmissionError("Exact GitHub artifact digest required")
    if any(type(x) is not int or x <= 0 for x in (run_id, artifact_id)):
        raise AdmissionError("Positive source run and artifact IDs required")
    digest = hashlib.sha256()
    total = 0
    hashes = {}
    for name, data in sorted(contents.items()):
        if not data:
            raise AdmissionError("Empty runtime asset: " + name)
        file_hash = _sha(data)
        total += len(data)
        if total > MAX_OUTPUT_BYTES:
            raise AdmissionError("Web release exceeds bounded capacity")
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\n")
        hashes[name] = file_hash
    revision = digest.hexdigest()[:16]
    base = f"{PREFIX}/releases/{revision}"
    entries = {}
    for name, data in sorted(contents.items()):
        key = f"{base}/{name}"
        entries[name] = {
            "key": key,
            "sha256": hashes[name],
            "bytes": len(data),
            "contentType": CONTENT_TYPES.get(Path(name).suffix.lower(), "application/octet-stream"),
            "url": f"{ORIGIN}/{key}",
        }
    return {
        "schema": 1,
        "application": "pawn-action",
        "environment": "staging",
        "sourceSha": source_sha,
        "sourceArtifact": {"runId": run_id, "artifactId": artifact_id, "digest": artifact_digest},
        "release": revision,
        "sha256": digest.hexdigest(),
        "index": entries["index.html"]["url"],
        "pointerKey": f"{PREFIX}/current.json",
        "publishAuthorized": False,
        "pages": {
            "perFileLimitBytes": PAGES_FILE_LIMIT,
            "filesTooLargeForPages": sorted(
                name for name, data in contents.items() if len(data) > PAGES_FILE_LIMIT
            ),
        },
        "files": entries,
    }


def prepare(archive: Path, artifact_digest: str, source_sha: str, run_id: int,
            artifact_id: int, destination: Path) -> dict:
    # Validate the complete GitHub ZIP digest, CRC, paths, file bounds and
    # required Godot assets before creating ANY output.
    verify_archive(archive, artifact_digest)
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise AdmissionError("Release destination already exists; refusing replacement")
    if not destination.parent.is_dir():
        raise AdmissionError("Release destination parent must already exist")
    with zipfile.ZipFile(archive) as zip_in:
        contents = {
            name: zip_in.read(name) for name in sorted(zip_in.namelist())
        }
    manifest = _build_manifest(contents, source_sha, artifact_digest, run_id, artifact_id)
    # Write in a temporary sibling and atomically move only when verified.
    with tempfile.TemporaryDirectory(prefix=".pawn-action-build-", dir=destination.parent) as tmp:
        staged = Path(tmp) / "candidate"
        runtime = staged / "runtime"
        runtime.mkdir(parents=True)
        for name, data in contents.items():
            path = runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (staged / "release.json").write_bytes(_render(manifest))
        validate(staged, source_sha)
        if destination.exists() or destination.is_symlink():
            raise AdmissionError("Release destination was created concurrently")
        os.rename(staged, destination)
    return manifest


def validate(destination: Path, source_sha: str) -> dict:
    if not SHA.fullmatch(source_sha):
        raise AdmissionError("Exact Pawn Action source SHA required")
    try:
        manifest = json.loads((destination / "release.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise AdmissionError("Candidate manifest missing or invalid: " + type(exc).__name__) from None
    if (not isinstance(manifest, dict)
            or manifest.get("application") != "pawn-action"
            or manifest.get("environment") != "staging"
            or manifest.get("sourceSha") != source_sha
            or manifest.get("publishAuthorized") is not False
            or manifest.get("pointerKey") != "pawn-action/current.json"):
        raise AdmissionError("Candidate has wrong ownership or source SHA")
    origin = manifest.get("sourceArtifact")
    if (not isinstance(origin, dict) or type(origin.get("runId")) is not int
            or type(origin.get("artifactId")) is not int
            or origin["runId"] <= 0 or origin["artifactId"] <= 0):
        raise AdmissionError("Candidate has invalid source run/artifact IDs")
    from pawn_action_source_admission import DIGEST
    if not isinstance(origin.get("digest"), str) or not DIGEST.fullmatch(origin["digest"]):
        raise AdmissionError("Candidate has invalid source archive digest")
    entries = manifest.get("files")
    if not isinstance(entries, dict) or not 4 <= len(entries) <= 128:
        raise AdmissionError("Candidate file inventory invalid")
    root = destination / "runtime"
    if not root.is_dir():
        raise AdmissionError("Candidate runtime directory missing")
    files = sorted(root.rglob("*"))
    if any(p.is_symlink() for p in (destination, root, *files)):
        raise AdmissionError("Symlink in candidate")
    if any(not p.is_file() for p in files):
        raise AdmissionError("Unexpected directory in candidate")
    if {p.relative_to(root).as_posix() for p in files} != set(entries):
        raise AdmissionError("Unexpected or missing candidate file")
    if set(p.name for p in destination.iterdir()) != {"runtime", "release.json"}:
        raise AdmissionError("Unexpected candidate root entry")
    contents = {p.relative_to(root).as_posix(): p.read_bytes() for p in files}
    expected = _build_manifest(contents, source_sha, origin["digest"], origin["runId"], origin["artifactId"])
    if manifest != expected:
        raise AdmissionError("Candidate bytes, content IDs or URLs do not match the manifest")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    cmd = sub.add_parser("prepare")
    cmd.add_argument("--zip", type=Path, required=True)
    cmd.add_argument("--digest", required=True)
    cmd.add_argument("--source-sha", required=True)
    cmd.add_argument("--run-id", type=int, required=True)
    cmd.add_argument("--artifact-id", type=int, required=True)
    cmd.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("validate")
    check.add_argument("--out", type=Path, required=True)
    check.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            manifest = prepare(args.zip, args.digest, args.source_sha,
                               args.run_id, args.artifact_id, args.out)
        else:
            manifest = validate(args.out, args.source_sha)
        print("PAWN_ACTION_R2_CANDIDATE_VERIFIED "
              + json.dumps({"release": manifest["release"], "sourceSha": manifest["sourceSha"],
                            "pagesUnsafe": manifest["pages"]["filesTooLargeForPages"]},
                           sort_keys=True))
        return 0
    except (AdmissionError, OSError, zipfile.BadZipFile) as exc:
        print("PAWN_ACTION_R2_CANDIDATE_BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
