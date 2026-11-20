#!/usr/bin/env python3
"""Prepare a closed-by-default Star Adventures Pages bundle; never deploy it.

This is a build contract, NOT an authorization switch or an Identity E2E check.
The preexisting public Pages publisher remains paused until a separate reviewed
cutover proves a real staging IdP, secret binding, alias denial and signed-in play.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from staradvs_pages import entrypoint_path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "edge" / "staradvs-identity-gate.mjs"
POLICY = ROOT / "config" / "staradvs-protected-release.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")
JS = re.compile(r"/assets/[A-Za-z0-9._-]+\.js\Z")
AUTH = {
    "provider": "shadowops-id",
    "audience": "staradvs",
    "issuer": "https://id-staging.shadowops.dpdns.org",
    "required": True,
}


class ProtectionError(Exception):
    pass


def policy_status(path: Path = POLICY) -> str:
    """There is intentionally no 'active' escape hatch in this release."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
            raise ProtectionError("Missing or unsafe protected-release policy")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ProtectionError("Invalid protected-release policy") from None
    if type(data) is not dict or data != {"mode": "pending-identity"}:
        raise ProtectionError("Unreviewed private cutover mode")
    return "pending-identity"


def _read(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ProtectionError("Invalid protected build file: " + path.name)
    data = path.read_bytes()
    if not data:
        raise ProtectionError("Empty protected build file: " + path.name)
    return data


def _root(dist: Path) -> None:
    if dist.is_symlink() or not dist.is_dir():
        raise ProtectionError("Invalid build directory")
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ProtectionError("Pages build must not contain symlink assets")
    if (dist / "_routes.json").exists() or (dist / "functions").exists():
        raise ProtectionError("Routes/Functions could bypass the canonical Worker")
    if (dist / "_worker.js").exists() and not (dist / "_worker.js").is_file():
        raise ProtectionError("Invalid edge Worker output")


def _manifest(dist: Path, source_sha: str, *, protected: bool) -> dict:
    if not SHA.fullmatch(source_sha):
        raise ProtectionError("Immutable source SHA required")
    try:
        data = json.loads(_read(dist / "release.json", 65536))
    except (ValueError, UnicodeError):
        raise ProtectionError("Malformed release manifest") from None
    keys = {"build", "environment", "entry_js"}
    if protected:
        keys.add("authentication")
    if type(data) is not dict or set(data) != keys:
        raise ProtectionError("Unexpected release manifest schema")
    if data["build"] != source_sha or data["environment"] != "staging":
        raise ProtectionError("Release belongs to another source/environment")
    entry = data["entry_js"]
    if type(entry) is not dict or set(entry) != {"path", "sha256"}:
        raise ProtectionError("Malformed JS integrity contract")
    path = entry["path"]
    if not isinstance(path, str) or not JS.fullmatch(path):
        raise ProtectionError("Nonlocal JS entrypoint")
    try:
        actual = entrypoint_path(_read(dist / "index.html", 700000))
    except (ValueError, UnicodeError, OSError) as exc:
        raise ProtectionError("Invalid HTML entrypoint") from None
    if actual != path:
        raise ProtectionError("HTML and release entrypoint mismatch")
    js = _read(dist / path.lstrip("/"), 16_000_000)
    if hashlib.sha256(js).hexdigest() != entry["sha256"]:
        raise ProtectionError("Release JS checksum mismatch")
    if protected and data["authentication"] != AUTH:
        raise ProtectionError("Release is not marked as requiring Star Adventures Identity")
    return data


def _trusted_worker() -> bytes:
    data = _read(WORKER, 100000)
    source = data.decode("utf-8")
    required = (
        "export const HOST='staging.staradvs.shadowops.dpdns.org'",
        "export const ISSUER='https://id-staging.shadowops.dpdns.org'",
        "export const AUDIENCE='staradvs'",
        "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL",
        "env.ASSETS.fetch(request)",
        "export default {fetch:handle}",
    )
    if not all(marker in source for marker in required):
        raise ProtectionError("Unrecognized Infra-owned Star Adventures Worker")
    return data


def prepare(dist: Path, source_sha: str) -> None:
    _root(dist)
    if (dist / "_worker.js").exists():
        raise ProtectionError("Refuse to overwrite an existing Pages Worker")
    data = _manifest(dist, source_sha, protected=False)
    worker = _trusted_worker()
    data["authentication"] = dict(AUTH)
    (dist / "_worker.js").write_bytes(worker)
    (dist / "release.json").write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    verify(dist, source_sha)


def verify(dist: Path, source_sha: str) -> None:
    _root(dist)
    _manifest(dist, source_sha, protected=True)
    if _read(dist / "_worker.js", 100000) != _trusted_worker():
        raise ProtectionError("Published Worker differs from approved Infra source")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("gate", "prepare", "verify"))
    parser.add_argument("--dist", default="")
    parser.add_argument("--sha", default="")
    args = parser.parse_args(argv)
    try:
        if args.operation == "gate":
            if args.dist or args.sha:
                raise ProtectionError("Gate cannot accept source-controlled overrides")
            policy_status()
            print("STARADVS_PROTECTED_PUBLICATION_PAUSED pending=identity-cutover")
            return 10
        if not args.dist or not args.sha:
            raise ProtectionError("Protected package requires exact directory and SHA")
        if args.operation == "prepare":
            prepare(Path(args.dist), args.sha)
        else:
            verify(Path(args.dist), args.sha)
        print("STARADVS_PROTECTED_PACKAGE_VERIFIED sha=" + args.sha)
        return 0
    except (ProtectionError, OSError, UnicodeError) as exc:
        print("STARADVS_PROTECTED_PACKAGE_BLOCKED " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
