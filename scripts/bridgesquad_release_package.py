#!/usr/bin/env python3
"""Seal the exact SHA-verified Bridge Squad HTML with Infra's own Identity edge.

No Cloudflare writes and no secret binding. Source admission and actual
production authentication remain independent, mandatory deployment gates.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import zipfile

import bridgesquad_source_admission as source

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "edge" / "bridgesquad-identity-gate.mjs"
AUTH = {"provider": "shadowops-id", "audience": "bridgesquad", "required": True}
GAME = "matthias-bridge-squad"
ENV = "production"
HOST = "bridgesquad.shadowops.dpdns.org"
REQUIRED_WORKER = (
    "export default {fetch:handle}",
    "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL",
    "https://id.shadowops.dpdns.org",
    "bridgesquad.shadowops.dpdns.org",
    "const claims=await authorize(cookie(request),env,options)",
    "if(url.protocol!=='https:'||url.host!==HOST)",
)


class PackageError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def trusted_edge() -> bytes:
    if EDGE.is_symlink() or not EDGE.is_file():
        raise PackageError("Missing or linked Infra-owned edge")
    data = EDGE.read_bytes()
    if not 1000 <= len(data) <= 100_000:
        raise PackageError("Unexpected trusted Worker size")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise PackageError("Invalid trusted Worker UTF-8") from exc
    if not all(term in text for term in REQUIRED_WORKER):
        raise PackageError("Expected exact-host and live Identity edge checks missing")
    return data


def metadata(source_sha: str, source_digest: str, html: bytes, edge: bytes) -> dict:
    return {
        "schema": 1, "application": GAME, "environment": ENV,
        "source_repository": source.SOURCE,
        "source_sha": source_sha,
        "source_artifact_digest": source_digest,
        "authentication": AUTH,
        "files": {
            "index.html": {"sha256": digest(html), "bytes": len(html)},
            "_worker.js": {"sha256": digest(edge), "bytes": len(edge)},
        },
    }


def prepare(archive: Path, zip_digest: str, sha: str, destination: Path) -> dict:
    """No extraction, no caller-supplied Worker, no overwrites."""
    if destination.exists() or destination.is_symlink():
        raise PackageError("Destination already exists; never overwrite a release")
    try:
        source.verify_archive(archive, zip_digest, sha)
    except source.AdmissionError as exc:
        raise PackageError("Unverified game source: " + str(exc)) from None
    edge = trusted_edge()
    with zipfile.ZipFile(archive) as z:
        html = z.read("index.html")
    result = metadata(sha, zip_digest, html, edge)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "index.html").write_bytes(html)
    (destination / "_worker.js").write_bytes(edge)
    (destination / "release.json").write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    verify(destination, zip_digest, sha)
    return result


def verify(destination: Path, zip_digest: str, sha: str) -> dict:
    if not source.SHA.fullmatch(sha) or not source.DIGEST.fullmatch(zip_digest):
        raise PackageError("Pinned source SHA and artifact digest required")
    if destination.is_symlink() or not destination.is_dir():
        raise PackageError("Release directory missing or linked")
    if {p.name for p in destination.iterdir()} != {"index.html", "_worker.js", "release.json"}:
        raise PackageError("Unexpected or missing release file")
    for p in destination.iterdir():
        if p.is_symlink() or not p.is_file():
            raise PackageError("Release contains linked or nonregular file")
    try:
        manifest = json.loads((destination / "release.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise PackageError("Release manifest unreadable") from None
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "application", "environment", "source_repository", "source_sha",
        "source_artifact_digest", "authentication", "files",
    }:
        raise PackageError("Unexpected Infra release manifest")
    if (type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["application"] != GAME or manifest["environment"] != ENV
            or manifest["source_repository"] != source.SOURCE
            or manifest["source_sha"] != sha
            or manifest["source_artifact_digest"] != zip_digest
            or manifest["authentication"] != AUTH):
        raise PackageError("Release identity or admission receipt mismatched")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != {"index.html", "_worker.js"}:
        raise PackageError("Unexpected release files")
    html = (destination / "index.html").read_bytes()
    edge = (destination / "_worker.js").read_bytes()
    if (not 64 <= len(html) <= source.MAX_HTML or
            not html.lstrip().lower().startswith(b"<!doctype html>") or
            b"<title>Matthias Bridge Squad" not in html):
        raise PackageError("HTML source missing or changed")
    if edge != trusted_edge():
        raise PackageError("Worker differs from reviewed Infra source")
    expected = metadata(sha, zip_digest, html, edge)
    if files != expected["files"]:
        raise PackageError("Release file bytes do not match manifest")
    return manifest


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 6 and argv[1] == "prepare":
            row = prepare(Path(argv[2]), argv[3], argv[4], Path(argv[5]))
            print("BRIDGESQUAD_SEALED_RELEASE_READY sha=" + row["source_sha"] +
                  " source_digest=" + row["source_artifact_digest"] +
                  " edge_digest=" + row["files"]["_worker.js"]["sha256"] +
                  " delivered=false identity_verified=false")
        elif len(argv) == 5 and argv[1] == "verify":
            row = verify(Path(argv[2]), argv[3], argv[4])
            print("BRIDGESQUAD_SEALED_RELEASE_VERIFIED sha=" + row["source_sha"] +
                  " delivered=false identity_verified=false")
        else:
            raise PackageError("Usage: prepare ZIP digest SHA OUTPUT | verify FOLDER digest SHA")
        return 0
    except (OSError, ValueError) as exc:
        print("BRIDGESQUAD_PACKAGE_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
