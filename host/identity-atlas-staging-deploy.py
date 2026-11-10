#!/opt/shadowops/oci-venv/bin/python -I
"""Atlas-only Identity staging release primitive. NOT installed or delegated yet.

A future independently protected workflow must verify signed-image provenance,
source ancestry, operator custody and human authorization before invoking this.
No local Mongo deployment or Atlas takeover-marker mutation is permitted.
"""
from __future__ import annotations

import fcntl
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, "/usr/local/lib/shadowops")
from identity_staging_atlas_admission import require_atlas_restore_evidence
from identity_staging_atlas_policy import validate_atlas_compose
from identity_staging_atlas_transition import (
    AtlasTransitionBlocked, TransitionCheckpoint, guarded_transition,
    image_from_atlas_container, IMAGE, PROJECT,
)
from shared_a1_host_guard import verify_shared_a1_containers

ROOT = Path("/etc/shadowops/identity-staging")
STATE = Path("/var/lib/shadowops/identity-staging")
HOST = "https://id-staging.shadowops.dpdns.org"
SNOOKER_CALLBACK = "https://staging.snooker.shadowops.dpdns.org/?shadowops=central"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
CONTAINER_ID = re.compile(r"[a-f0-9]{12,64}\Z")


class AtlasReleaseBlocked(ValueError):
    pass


def run(args, *, digest=None, timeout=180):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "NO_PROXY": "*"}
    if digest is not None:
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise AtlasReleaseBlocked("Invalid Compose image digest")
        env["IDENTITY_IMAGE_DIGEST"] = digest
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        raise AtlasReleaseBlocked("Fixed Atlas operation unavailable") from None
    if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > 1048576:
        raise AtlasReleaseBlocked("Fixed Atlas operation failed")
    return result.stdout


def load_operator(name, path):
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def root_file(path, *, private=False):
    meta = path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != 0 or meta.st_mode & (0o077 if private else 0o022)):
        raise AtlasReleaseBlocked("Untrusted Atlas operator file")


def live_image(runner):
    ids = runner(["docker", "ps", "-aq", "--filter",
                  "label=com.docker.compose.project=" + PROJECT,
                  "--filter", "label=com.docker.compose.service=identity"]).splitlines()
    if len(ids) != 1 or not CONTAINER_ID.fullmatch(ids[0]):
        raise AtlasReleaseBlocked("Ambiguous Atlas Identity container")
    rows = json.loads(runner(["docker", "inspect", ids[0]]))
    digest = image_from_atlas_container(rows)
    labels = rows[0]["Config"]["Labels"]
    source_sha = labels.get("org.opencontainers.image.revision")
    if (not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)
            or labels.get("org.opencontainers.image.source")
               != "https://github.com/evilsysadmin/shadowops-infra"):
        raise AtlasReleaseBlocked("Identity image provenance unavailable")
    return digest, source_sha


def public_release_sha(runner):
    response = json.loads(runner([
        "curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
        "--max-time", "12", "--header", "Cache-Control: no-cache",
        HOST + "/api/identity/release"], timeout=18))
    if (not isinstance(response, dict) or set(response) != {"service", "environment", "source_sha"}
            or response["service"] != "shadowops-identity"
            or response["environment"] != "staging"
            or not isinstance(response["source_sha"], str)
            or not SHA.fullmatch(response["source_sha"])):
        raise AtlasReleaseBlocked("Public Identity release unverifiable")
    return response["source_sha"]


def snooker_login_ready(runner):
    html = runner([
        "curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
        "--max-time", "12", "--header", "Cache-Control: no-cache",
        HOST + "/login?app=snooker"], timeout=18)
    return SNOOKER_CALLBACK in html


def update(digest, source_sha, *, runner=run, preflight=None, backup_operator=None,
           journal=None, check_shared=verify_shared_a1_containers):
    if (not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            or not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)):
        raise AtlasReleaseBlocked("Invalid immutable release identity")
    preflight = preflight or load_operator(
        "atlas_release_preflight", "/usr/local/sbin/shadowops-identity-atlas-preflight")
    backup_operator = backup_operator or load_operator(
        "atlas_release_backup", "/usr/local/sbin/shadowops-identity-atlas-backup")
    preflight.trusted_paths()
    root_file(STATE / "atlas-active", private=True)
    root_file(ROOT / "atlas-compose.yaml")
    require_atlas_restore_evidence(backup_operator.private_config(), STATE)
    check_shared()
    previous, previous_sha = live_image(runner)
    if previous == digest:
        raise AtlasReleaseBlocked("No Atlas image change")
    if public_release_sha(runner) != previous_sha:
        raise AtlasReleaseBlocked("Live public release differs from Atlas container")
    if preflight.execute(digest, source_sha) != (
            "IDENTITY_ATLAS_PREFLIGHT_OK source_sha=" + source_sha + " digest=" + digest):
        raise AtlasReleaseBlocked("Candidate Atlas preflight not proven")
    compose = ["docker", "compose", "--project-directory", str(ROOT),
               "-f", str(ROOT / "atlas-compose.yaml")]
    for selected in (previous, digest):
        normalized = json.loads(runner(compose + ["config", "--format", "json"], digest=selected))
        validate_atlas_compose(normalized, selected)

    def activate(image):
        runner(compose + ["up", "--detach", "--no-deps", "--wait",
                          "--wait-timeout", "150", "--no-build", "--pull", "never",
                          "--force-recreate", "identity"], digest=image, timeout=195)

    def verify(image):
        try:
            actual_digest, actual_sha = live_image(runner)
            expected_sha = source_sha if image == digest else previous_sha
            return (actual_digest == image and actual_sha == expected_sha
                    and public_release_sha(runner) == expected_sha
                    and (image != digest or snooker_login_ready(runner)))
        except (AtlasReleaseBlocked, AtlasTransitionBlocked, OSError,
                ValueError, TypeError, KeyError, IndexError):
            return False

    guarded_transition(previous, digest,
                       journal=journal or TransitionCheckpoint(STATE),
                       activate=activate, verify=verify)
    return "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + source_sha + " digest=" + digest


def main():
    try:
        if (os.geteuid() != 0 or len(sys.argv) != 4 or sys.argv[1] != "deploy"):
            raise AtlasReleaseBlocked("Invalid root operator request")
        # O_NOFOLLOW and exclusive flock prevent symlink and concurrent release tricks.
        fd = os.open(STATE / "deploy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077):
                raise AtlasReleaseBlocked("Untrusted release lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(update(sys.argv[2], sys.argv[3]))
        finally:
            os.close(fd)
        return 0
    except Exception as exc:
        # Never forward Docker, Atlas, environment, or private traceback material.
        print("IDENTITY_ATLAS_DEPLOY_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
