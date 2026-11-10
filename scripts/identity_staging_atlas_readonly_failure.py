#!/usr/bin/env python3
"""Read-only host evidence after an Atlas SSH release was BLOCKED.

Root over the established trusted Cloudflare SSH stdin channel. No service
restart, backup, repair, marker mutation, Docker config contents or secrets.
The report includes only fixed categorical values and cannot reveal metadata.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

STATE = Path("/var/lib/shadowops/identity-staging")
CONF = Path("/etc/shadowops/identity-staging")
OPERATOR = Path("/usr/local/sbin/shadowops-identity-atlas-deploy")
INSTALLED_SOURCE = Path("/opt/shadowops-infra/host/identity-atlas-staging-deploy.py")
DIGEST = re.compile(r"ghcr[.]io/evilsysadmin/shadowops-identity@sha256:[a-f0-9]{64}\Z")
CID = re.compile(r"[a-f0-9]{12,64}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
OLD_SHA = "34d5aa2f4db3f522336a150266ac21f94d3ce95f"
NEW_SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
PROJECT = "shadowops-identity-staging"


def metadata(path, *, private=False, expected_owner=0):
    try:
        item = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unsafe"
    if (not stat.S_ISREG(item.st_mode) or item.st_uid != expected_owner
            or item.st_mode & (0o077 if private else 0o022)):
        return "unsafe"
    return "trusted"


def operator_status():
    if metadata(OPERATOR) != "trusted" or metadata(INSTALLED_SOURCE) != "trusted":
        return "untrusted"
    try:
        installed = hashlib.sha256(OPERATOR.read_bytes()).digest()
        source = hashlib.sha256(INSTALLED_SOURCE.read_bytes()).digest()
    except OSError:
        return "untrusted"
    return "matched" if installed == source else "mismatch"


def checkpoint_status():
    state = metadata(STATE / "atlas-deploy-pending.json", private=True)
    return {"missing": "absent", "trusted": "present", "unsafe": "unsafe"}[state]


def read_receipt(path):
    if metadata(path, private=True) != "trusted":
        return None
    if path.stat().st_size > 8192:
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    return obj if isinstance(obj, dict) else None


def freshness(record, now):
    if (not isinstance(record, dict) or record.get("schema") != 1
            or record.get("backend") != "atlas"
            or record.get("environment") != "staging"):
        return False
    try:
        stamp = datetime.fromisoformat(record["created_at"])
    except (TypeError, ValueError, KeyError):
        return False
    return (stamp.tzinfo is not None and stamp <= now + timedelta(minutes=5)
            and now - stamp <= timedelta(hours=24))


def backup_restore_metadata(now):
    backup = read_receipt(STATE / "last-atlas-backup.json")
    restore = read_receipt(STATE / "last-atlas-restore.json")
    backup_ok = (freshness(backup, now)
                 and isinstance(backup.get("sha256"), str)
                 and HEX.fullmatch(backup["sha256"]) is not None
                 and isinstance(backup.get("cluster_sha256"), str)
                 and HEX.fullmatch(backup["cluster_sha256"]) is not None)
    restore_ok = (backup_ok and freshness(restore, now)
                  and restore.get("result") == "quarantine-restore-verified"
                  and restore.get("backup_sha256") == backup["sha256"]
                  and restore.get("cluster_sha256") == backup["cluster_sha256"])
    # Metadata consistency only. The root release operator independently
    # verifies the authenticated encrypted snapshot and restore evidence.
    return "fresh-metadata" if backup_ok else "unverified", (
        "matching-metadata" if restore_ok else "unverified")


def docker(args, *, max_bytes=131072):
    try:
        item = subprocess.run(["docker", *args], capture_output=True, text=True,
                              timeout=12, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if item.returncode or not isinstance(item.stdout, str) or len(item.stdout) > max_bytes:
            return None
        return item.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def container_status():
    ids = docker(["ps", "-aq", "--filter",
                  "label=com.docker.compose.project=" + PROJECT,
                  "--filter", "label=com.docker.compose.service=identity"])
    if ids is None:
        return "unverified", "unverified"
    lines = ids.splitlines()
    if len(lines) != 1 or CID.fullmatch(lines[0]) is None:
        return "ambiguous", "unverified"
    # Fixed Go-template fields; never read the container's Env, logs or secrets.
    fmt = ("{{json .Config.Image}}\t{{json .Config.Labels}}\t"
           "{{json .Mounts}}\t{{json .NetworkSettings.Networks}}\t"
           "{{json .State.Status}}\t{{json .State.Health.Status}}")
    raw = docker(["inspect", "--type", "container", "--format", fmt, lines[0]])
    if raw is None:
        return "unverified", "unverified"
    parts = raw.split("\t")
    if len(parts) != 6:
        return "unverified", "unverified"
    try:
        image, labels, mounts, networks, state, health = (json.loads(x) for x in parts)
    except (ValueError, TypeError):
        return "unverified", "unverified"
    if not isinstance(labels, dict):
        return "unverified", "unverified"
    revision = labels.get("org.opencontainers.image.revision")
    version = ("previous" if revision == OLD_SHA else
               "candidate" if revision == NEW_SHA else "other")
    expected = {
        PROJECT + "-origin", PROJECT + "-atlas-egress",
    }
    bound = ([m for m in mounts if isinstance(m, dict)
              and m.get("Destination") == "/run/secrets/identity-staging.json"]
             if isinstance(mounts, list) else [])
    if (not isinstance(networks, dict) or set(networks) != expected
            or len(bound) != 1 or bound[0].get("Source") !=
            "/etc/shadowops/identity-staging/atlas-service.json"
            or bound[0].get("RW") is not False or bound[0].get("Type") != "bind"):
        return "not-atlas", version
    if (not isinstance(image, str) or DIGEST.fullmatch(image) is None
            or labels.get("com.docker.compose.project") != PROJECT
            or labels.get("com.docker.compose.service") != "identity"
            or labels.get("org.opencontainers.image.source")
            != "https://github.com/evilsysadmin/shadowops-infra"):
        return "untrusted-image", version
    if state != "running" or health != "healthy":
        return "unhealthy", version
    return "atlas-healthy", version


def inspect():
    if os.geteuid() != 0:
        return "IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=not-root"
    operator = operator_status()
    marker = metadata(STATE / "atlas-active", private=True)
    compose = metadata(CONF / "atlas-compose.yaml")
    checkpoint = checkpoint_status()
    backup, restore = backup_restore_metadata(datetime.now(timezone.utc))
    container, version = container_status()
    return ("IDENTITY_ATLAS_HOST_DIAG"
            + " operator=" + operator
            + " marker=" + marker
            + " compose=" + compose
            + " checkpoint=" + checkpoint
            + " backup=" + backup
            + " restore=" + restore
            + " container=" + container
            + " image_source=" + version)


def main():
    if sys.argv[1:]:
        print("IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=arguments")
        return 1
    try:
        result = inspect()
    except Exception:
        print("IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=audit-error")
        return 1
    print(result)
    return 0 if result.startswith("IDENTITY_ATLAS_HOST_DIAG ") else 1


if __name__ == "__main__":
    raise SystemExit(main())
