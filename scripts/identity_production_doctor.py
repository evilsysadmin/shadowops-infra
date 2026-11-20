#!/usr/bin/env python3
"""Read-only LOCAL prerequisite inventory for ShadowOps Identity production.

This deliberately NEVER opens secret contents, connects to Mongo/Docker/OCI,
or invokes any operator. Output is restricted to fixed labels and states:
no environment values, credentials, hostnames or filesystem paths.
It is a diagnostic, NOT a production admission or authorization.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import sys

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# Keys and type are fixed in code; never display environment values.
GROUPS = (
    ("mongo", (
        ("IDENTITY_PRODUCTION_MONGO_ADMIN_URI_FILE", "file"),
        ("IDENTITY_PRODUCTION_MONGO_CA_FILE", "file"),
        ("IDENTITY_PRODUCTION_MONGO_REPLICA_SET", "text"),
    )),
    ("origin", (
        ("IDENTITY_PRODUCTION_IMAGE_DIGEST", "digest"),
        ("IDENTITY_PRODUCTION_SOURCE_SHA", "sha"),
        ("IDENTITY_PRODUCTION_BUNDLE_FILE", "file"),
        ("IDENTITY_PRODUCTION_ORIGIN_CA_FILE", "file"),
    )),
    ("tunnel", (
        ("IDENTITY_PRODUCTION_TUNNEL_DIGEST", "digest"),
        ("IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE", "file"),
        ("IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE", "file"),
        ("IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE", "file"),
    )),
)


def presence(env: dict[str, str], name: str, kind: str) -> str:
    value = env.get(name, "")
    if not value:
        return "missing"
    if kind == "sha":
        return "set" if SHA.fullmatch(value) else "invalid"
    if kind == "digest":
        return "set" if DIGEST.fullmatch(value) else "invalid"
    if kind == "text":
        return "set" if value.strip() else "invalid"
    if kind != "file":
        raise ValueError("unknown diagnostic category")
    # lstat, never follow a symlink or read secret bytes.
    try:
        path = Path(value)
        if not path.is_absolute():
            return "invalid"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return "invalid"
        return "present"
    except (OSError, ValueError):
        return "unavailable"


def audit(environ=None, *, uid=None, tty=None, has_docker=None,
          has_pymongo=None, has_yaml=None) -> list[str]:
    env = os.environ if environ is None else environ
    uid = os.geteuid() if uid is None else uid
    tty = sys.stdin.isatty() if tty is None else tty
    has_docker = shutil.which("docker") is not None if has_docker is None else has_docker
    has_pymongo = importlib.util.find_spec("pymongo") is not None if has_pymongo is None else has_pymongo
    has_yaml = importlib.util.find_spec("yaml") is not None if has_yaml is None else has_yaml

    lines = ["IDENTITY_PRODUCTION_DOCTOR scope=local read_only=yes secrets=not-opened network=not-probed"]
    for group, fields in GROUPS:
        values = " ".join(name.lower().removeprefix("identity_production_") +
                          "=" + presence(env, name, kind) for name, kind in fields)
        lines.append("IDENTITY_PRODUCTION_REQUIREMENTS phase=" + group + " " + values)
    lines.append(
        "IDENTITY_PRODUCTION_OPERATOR host=local-only "
        "root=" + ("yes" if uid == 0 else "no") +
        " tty=" + ("yes" if tty else "no") +
        " ci=" + ("yes" if env.get("CI") or env.get("GITHUB_ACTIONS") else "no") +
        " docker_cli=" + ("yes" if has_docker else "no") +
        " pymongo=" + ("yes" if has_pymongo else "no") +
        " pyyaml=" + ("yes" if has_yaml else "no")
    )
    lines.append(
        "IDENTITY_PRODUCTION_NEXT run_on=authorized-production-host "
        "note=presence-does-not-verify-mongo-tls-image-or-identity"
    )
    return lines


def main(argv: list[str]) -> int:
    if argv:
        print("Usage: identity_production_doctor.py", file=sys.stderr)
        return 2
    for line in audit():
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
