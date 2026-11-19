#!/usr/bin/env python3
"""Read-only admission for an *operator-selected* production Identity Compose run.

Does not read the bundle bytes, access Mongo, pull images, contact OCI, publish
ports, create files or start containers. Never emit credential values or paths.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys

IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PRODUCTION_UID = 65532
COMPOSE_PATH = Path(__file__).resolve().parents[1] / "compose.identity.production.yaml"

class Refused(ValueError):
    pass

def validate(image_digest: str, bundle_file: str, *, lstat=os.lstat) -> None:
    if not IMAGE_DIGEST.fullmatch(image_digest):
        raise Refused("image digest must be an immutable sha256 reference")
    if not bundle_file or "\x00" in bundle_file:
        raise Refused("invalid bundle path")
    path = Path(bundle_file)
    if not path.is_absolute() or str(path) == "/":
        raise Refused("bundle path must be absolute")
    # Host-level links are refused, not resolved silently. Docker's bind mount
    # does not create a missing host path (see Compose create_host_path=false).
    try:
        for part in (path, *path.parents):
            meta = lstat(part)
            if stat.S_ISLNK(meta.st_mode):
                raise Refused("symlink in bundle path")
        meta = lstat(path)
    except OSError as exc:
        raise Refused("private bundle unavailable") from exc
    mode = stat.S_IMODE(meta.st_mode)
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != PRODUCTION_UID or
            mode not in (0o400, 0o600) or meta.st_size < 1 or meta.st_size > 131072):
        raise Refused("bundle must be a private regular file readable by image UID")
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    expected = (
        "ghcr.io/evilsysadmin/shadowops-identity-production-candidate@",
        "command: [\"serve-ready\"]",
        'user: "65532:65532"',
        "read_only: true",
        "cap_drop: [ALL]",
        'security_opt: ["no-new-privileges:true"]',
        "host_ip: 127.0.0.1",
        "create_host_path: false",
        "restart: \"no\"",
    )
    if any(snippet not in text for snippet in expected):
        raise Refused("production Compose security contract changed")

def main(argv: list[str]) -> int:
    if argv != ["inspect"]:
        print("Usage: identity_production_compose_preflight.py inspect", file=sys.stderr)
        return 2
    try:
        validate(os.environ.get("IDENTITY_PRODUCTION_IMAGE_DIGEST", ""),
                 os.environ.get("IDENTITY_PRODUCTION_BUNDLE_FILE", ""))
    except (Refused, UnicodeError, OSError):
        print("IDENTITY_PRODUCTION_COMPOSE_REFUSED", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_COMPOSE_PREFLIGHT_OK digest=pinned bundle=private ingress=loopback-only deploy=none")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
