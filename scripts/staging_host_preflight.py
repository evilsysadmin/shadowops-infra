#!/usr/bin/env python3
"""Read-only OCI staging preflight: digest, database scope and secret mounts.

Run on the staging host before invoking Docker Compose. No network calls,
credential output, Docker mutations or production deployment.
"""
from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Callable, Mapping, NamedTuple


DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
DATABASE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CONTAINER_UID = 65532
CONTAINER_GID = 65532


class PreflightError(ValueError):
    """A staging-only contract is not safe to deploy."""


class Secret(NamedTuple):
    device: int
    inode: int


def _mounted_secret(
    filename: str,
    minimum: int,
    validator: Callable[[bytes], bool],
    loader=None,
) -> Secret:
    # The actual file path is deliberately omitted from all errors.
    if not filename or not Path(filename).is_absolute():
        raise PreflightError("secret path must be absolute")
    try:
        if loader is None:
            metadata, contents = os.lstat(filename), Path(filename).read_bytes()
        else:
            metadata, contents = loader(filename)
    except (OSError, UnicodeError) as exc:
        raise PreflightError("secret file cannot be inspected") from exc

    mode = metadata.st_mode
    if not stat.S_ISREG(mode):
        raise PreflightError("secret file is not regular")
    if mode & 0o007:
        raise PreflightError("secret file is world-accessible")
    owned_read = metadata.st_uid == CONTAINER_UID and bool(mode & stat.S_IRUSR)
    group_read = metadata.st_gid == CONTAINER_GID and bool(mode & stat.S_IRGRP)
    if not (owned_read or group_read):
        raise PreflightError("secret file is not readable by container UID/GID 65532")
    if len(contents) < minimum or len(contents) > 4096:
        raise PreflightError("secret file size is outside allowed bounds")
    if not validator(contents.removesuffix(b"\n").removesuffix(b"\r")):
        raise PreflightError("secret contents are invalid")
    return Secret(metadata.st_dev, metadata.st_ino)


def verify_staging_environment(env: Mapping[str, str], loader=None) -> str:
    digest = env.get("CHRONICLES_IMAGE_DIGEST", "")
    database = env.get("CHRONICLES_MONGODB_DATABASE", "")
    if not DIGEST.fullmatch(digest):
        raise PreflightError("staging image must be an immutable sha256 digest")
    if database != "chronicles_staging":
        raise PreflightError("MongoDB name must be exactly chronicles_staging")
    if env.get("CHRONICLES_ENABLE_READ_API") not in (None, "", "true"):
        raise PreflightError("unexpected staging read API configuration")
    if env.get("CHRONICLES_ENVIRONMENT") not in (None, "", "staging"):
        raise PreflightError("production environment forbidden in staging preflight")

    mongo = _mounted_secret(
        env.get("CHRONICLES_MONGO_SECRET_FILE", ""),
        12,
        lambda value: value.startswith((b"mongodb://", b"mongodb+srv://"))
        and b"\x00" not in value and b"\n" not in value,
        loader,
    )
    jwt = _mounted_secret(
        env.get("CHRONICLES_STAGING_JWT_SECRET_FILE", ""),
        32,
        lambda value: b"\x00" not in value,
        loader,
    )
    if mongo == jwt:
        raise PreflightError("MongoDB and JWT credentials must be separate files")
    return digest


def main() -> int:
    try:
        digest = verify_staging_environment(os.environ)
    except PreflightError as exc:
        print("CHRONICLES_STAGING_PREFLIGHT_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print("CHRONICLES_STAGING_PREFLIGHT_OK digest=" + digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
