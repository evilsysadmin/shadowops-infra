#!/usr/bin/env python3
"""Build and verify a DENY-ALL static Pages staging shell, never a live game."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "workers/pawn-action-staging/edge.mjs"
HOST = "staging.pawnaction.shadowops.dpdns.org"
# A publicly visible identity marker, not an auth or content-integrity proof.
SHELL_MARKER_HEADER = "X-Pawn-Action-Holding-Shell"
SHELL_MARKER_VALUE = "deny-only-v1"
FALLBACK = ("""<!doctype html>
<html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pawn Action · Staging bloqueado</title>
<h1>Pawn Action</h1><p>Staging protegido. El juego todavía no está disponible.</p>
""").encode("utf-8")
HEADERS = ("""/*
  Cache-Control: no-store, max-age=0
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
""").encode("utf-8")

class ShellError(ValueError):
    pass

def expected() -> dict[str, bytes]:
    code = SOURCE.read_bytes()
    for marker in (HOST.encode(), b"state: 'locked'", b"game_ready: false",
                   b"export default {fetch: handle}",
                   ("'" + SHELL_MARKER_HEADER + "': '" + SHELL_MARKER_VALUE + "'").encode()):
        if marker not in code:
            raise ShellError("Staging Worker source missing its deny-only contract")
    # Hard reject direct static/game forwarding in executable source lines.
    for line in code.splitlines():
        if line.lstrip().startswith(b"//"):
            continue
        if b"ASSETS.fetch(" in line or b"pawn-slug-godot/current.json" in line:
            raise ShellError("Holding shell must never publish gameplay or legacy pointer")
    return {"_worker.js": code, "index.html": FALLBACK, "_headers": HEADERS}

def verify(folder: Path) -> dict:
    if not folder.is_dir() or folder.is_symlink():
        raise ShellError("Missing or symlinked Pages shell")
    files = expected()
    if {p.name for p in folder.iterdir()} != set(files):
        raise ShellError("Unexpected or missing Pages shell files")
    for name, data in files.items():
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise ShellError("Pages shell differs from the approved source: " + name)
    return {"hostname": HOST, "locked": True, "gameFiles": 0,
            "edgeSha256": hashlib.sha256(files["_worker.js"]).hexdigest()}

def build(folder: Path) -> dict:
    folder = folder.absolute()
    if folder.exists() or folder.is_symlink():
        raise ShellError("Refusing to overwrite an existing Pages shell")
    if not folder.parent.is_dir():
        raise ShellError("Output parent directory missing")
    files = expected()
    with tempfile.TemporaryDirectory(prefix=".pawn-action-shell-", dir=folder.parent) as tmp:
        stage = Path(tmp) / "site"
        stage.mkdir()
        for name, data in files.items():
            (stage / name).write_bytes(data)
        verify(stage)
        if folder.exists() or folder.is_symlink():
            raise ShellError("Output directory appeared during build")
        os.rename(stage, folder)
    return verify(folder)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(args.out) if args.action == "build" else verify(args.out)
        print("PAWN_ACTION_LOCKED_PAGES_SHELL_OK " + str(result))
        return 0
    except (ShellError, OSError) as exc:
        print("PAWN_ACTION_LOCKED_PAGES_SHELL_BLOCKED " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
