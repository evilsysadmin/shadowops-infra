#!/usr/bin/env python3
"""Explain a blocked Atlas Identity release with exact PRE-MUTATION gates only.

Streamed by an authorized human over existing Access SSH to root's installed
Python interpreter. Imports the same installed release validators as the deploy
operator, but NEVER runs its update/main/preflight.execute/guarded_transition,
never opens a write lock, never pulls an image or changes Docker/Atlas/Identity.
All exceptions are reduced to a fixed gate name, never their text or data.
"""
from __future__ import annotations

import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

OPERATOR = Path("/usr/local/sbin/shadowops-identity-atlas-deploy")
SOURCE = Path("/opt/shadowops-infra/host/identity-atlas-staging-deploy.py")
PREFLIGHT = Path("/usr/local/sbin/shadowops-identity-atlas-preflight")
BACKUP = Path("/usr/local/sbin/shadowops-identity-atlas-backup")
CHECKPOINT = Path("/var/lib/shadowops/identity-staging/atlas-deploy-pending.json")
IMAGE = "ghcr.io/evilsysadmin/shadowops-identity@"
DIGEST = "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91"
SOURCE_SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
OLD_SHA = "34d5aa2f4db3f522336a150266ac21f94d3ce95f"
ALLOWED_STAGES = frozenset({
    "authority", "checkpoint", "trusted-paths", "atlas-marker",
    "backup-restore-crypto", "shared-host", "live-container", "public-source",
    "compose-previous", "compose-candidate", "candidate-cache",
})


class GateBlocked(Exception):
    def __init__(self, stage):
        assert stage in ALLOWED_STAGES
        self.stage = stage
        super().__init__("Release gate blocked")


def ensure(stage, fn):
    try:
        return fn()
    except Exception:
        raise GateBlocked(stage) from None


def trusted_code(path):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError("Untrusted code")
    if path.is_symlink():
        raise ValueError("Symlink")
    return path.read_bytes()


def module(name, path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    loaded = importlib.util.module_from_spec(spec)
    loader.exec_module(loaded)
    return loaded


def verify_authority():
    if hashlib.sha256(trusted_code(OPERATOR)).digest() != hashlib.sha256(trusted_code(SOURCE)).digest():
        raise ValueError("Installed release operator not matching root checkout")
    for path in (PREFLIGHT, BACKUP):
        trusted_code(path)


def require_no_pending():
    # Never open or clear the checkpoint. A pending attempt needs human review.
    try:
        CHECKPOINT.lstat()
    except FileNotFoundError:
        return
    raise ValueError("Atlas release journal must be reconciled")


def check_paths(release, preflight):
    preflight.trusted_paths()
    release.root_file(release.STATE / "atlas-active", private=True)
    release.root_file(release.ROOT / "atlas-compose.yaml")


def check_backup(release, backup):
    # Real decrypt/hash and rehearsal matching, not just timestamp metadata.
    release.require_atlas_restore_evidence(backup.private_config(), release.STATE)


def check_container(release):
    previous, sha = release.live_image(release.run)
    if sha != OLD_SHA or previous == DIGEST:
        raise ValueError("Unexpected active Atlas release")
    return previous, sha


def check_public(release, previous_sha):
    if release.public_release_sha(release.run) != previous_sha:
        raise ValueError("Public source and running container disagree")


def check_compose(release, digest):
    compose = ["docker", "compose", "--project-directory", str(release.ROOT),
               "-f", str(release.ROOT / "atlas-compose.yaml")]
    config = json.loads(release.run(compose + ["config", "--format", "json"], digest=digest))
    release.validate_atlas_compose(config, digest)


def cached_candidate(release):
    # Docker image inspect is local and read-only. Missing cache is informative;
    # the real preflight would pull it, and this audit deliberately does NOT.
    try:
        raw = release.run(["docker", "image", "inspect", IMAGE + DIGEST,
                           "--format", "{{json .Config.Labels}}"], timeout=15)
    except Exception:
        return "not-cached"
    try:
        labels = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("Untrusted local image labels") from None
    if (not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.revision") != SOURCE_SHA
            or labels.get("org.opencontainers.image.source")
               != "https://github.com/evilsysadmin/shadowops-infra"):
        raise ValueError("Cached image provenance mismatch")
    return "matched"


def evaluate(*, root_uid=os.geteuid, load=module):
    if root_uid() != 0:
        raise GateBlocked("authority")
    ensure("authority", verify_authority)
    ensure("checkpoint", require_no_pending)
    release = ensure("authority", lambda: load("atlas_release_audit", OPERATOR))
    preflight = ensure("authority", lambda: load("atlas_preflight_audit", PREFLIGHT))
    backup = ensure("authority", lambda: load("atlas_backup_audit", BACKUP))
    ensure("trusted-paths", lambda: preflight.trusted_paths())
    ensure("atlas-marker", lambda: release.root_file(release.STATE / "atlas-active", private=True))
    ensure("atlas-marker", lambda: release.root_file(release.ROOT / "atlas-compose.yaml"))
    ensure("backup-restore-crypto", lambda: check_backup(release, backup))
    ensure("shared-host", release.verify_shared_a1_containers)
    previous, previous_sha = ensure("live-container", lambda: check_container(release))
    ensure("public-source", lambda: check_public(release, previous_sha))
    # Read-only config render+strict policy validation of BOTH old and candidate.
    ensure("compose-previous", lambda: check_compose(release, previous))
    ensure("compose-candidate", lambda: check_compose(release, DIGEST))
    cache = ensure("candidate-cache", lambda: cached_candidate(release))
    return ("IDENTITY_ATLAS_RELEASE_GATES_OK"
            + " preactivation=verified"
            + " cached_candidate=" + cache
            + " candidate_preflight=not-run"
            + " transition=not-attempted")


def main():
    if sys.argv[1:]:
        print("IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=authority")
        return 1
    try:
        result = evaluate()
    except GateBlocked as exc:
        print("IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=" + exc.stage)
        return 0
    except Exception:
        print("IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=authority")
        return 0
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
