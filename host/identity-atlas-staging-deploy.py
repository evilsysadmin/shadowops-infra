#!/opt/shadowops/oci-venv/bin/python -I
"""Atlas-only Identity staging release primitive. NOT installed or delegated yet.

A future independently protected workflow must verify signed-image provenance,
source ancestry, operator custody and human authorization before invoking this.
No local Mongo deployment or Atlas takeover-marker mutation is permitted.
"""
from __future__ import annotations

import fcntl
from copy import deepcopy
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
    image_from_atlas_container, IMAGE, PROJECT, CONFIG, SNOOKER_CONFIG,
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


def run(args, *, digest=None, config_source=None, timeout=180):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "NO_PROXY": "*"}
    if digest is not None:
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise AtlasReleaseBlocked("Invalid Compose image digest")
        env["IDENTITY_IMAGE_DIGEST"] = digest
    if config_source is not None:
        if config_source not in (CONFIG, SNOOKER_CONFIG):
            raise AtlasReleaseBlocked("Untrusted Compose config choice")
        env["IDENTITY_ATLAS_SERVICE_CONFIG"] = config_source
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


def live_image(runner, config_source=CONFIG):
    ids = runner(["docker", "ps", "-aq", "--filter",
                  "label=com.docker.compose.project=" + PROJECT,
                  "--filter", "label=com.docker.compose.service=identity"]).splitlines()
    if len(ids) != 1 or not CONTAINER_ID.fullmatch(ids[0]):
        raise AtlasReleaseBlocked("Ambiguous Atlas Identity container")
    rows = json.loads(runner(["docker", "inspect", ids[0]]))
    digest = image_from_atlas_container(rows, config_source=config_source)
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


def require_isolated_config():
    """Admit staged candidate, never modify the legacy rollback configurations."""
    prepare = load_operator(
        "atlas_release_candidate_private", "/usr/local/sbin/shadowops-identity-atlas-prepare")
    from identity_staging_atlas_snooker_config import candidate_config
    prepare.trusted_dir(ROOT)
    candidate_path = ROOT / "atlas-snooker-service.json"
    metadata = candidate_path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 65532
            or stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_size > 131072):
        raise AtlasReleaseBlocked("Untrusted isolated Snooker configuration")
    local = prepare.load_private(ROOT / "service.json", 65532)
    legacy = prepare.load_private(ROOT / "atlas-service.json", 65532)
    candidate = prepare.load_private(candidate_path, 65532)
    # Check that the new file differs by exactly one Snooker consumer, and
    # Atlas, TLS, signing, admin and all previous consumer credentials match.
    vault_shape = deepcopy(local)
    vault_shape["consumers"] = deepcopy(candidate.get("consumers"))
    if candidate_config(local, legacy, vault_shape) != candidate:
        raise AtlasReleaseBlocked("Unexpected Snooker candidate configuration")


# Only these fixed labels may appear in operator output. Never expose exception
# text, Docker command output, private credentials, URLs, or container metadata.
STAGES = frozenset({
    "request", "lock", "candidate-identity", "trusted-paths", "atlas-marker",
    "backup-restore", "shared-host", "live-container", "public-source",
    "candidate-config", "candidate-preflight", "compose-previous", "compose-candidate",
    "transition-start", "candidate-activation", "candidate-inspect",
    "candidate-public", "candidate-audience", "rollback-activation",
    "rollback-inspect", "rollback-public", "complete",
})
ROLLBACK_STATES = frozenset({"not-started", "attempted", "verified", "unverified"})


def update(digest, source_sha, *, runner=run, preflight=None, backup_operator=None,
           journal=None, check_shared=verify_shared_a1_containers, progress=None):
    # The optional mutable tracker is output-only, never an instruction. It
    # records the FIRST failed candidate stage across verified rollback, rather
    # than exposing arbitrary errors or overwriting that stage with rollback.
    def mark(stage):
        if progress is not None:
            progress["stage"] = stage

    def fail():
        if progress is not None:
            progress.setdefault("failure", progress["stage"])

    mark("candidate-identity")
    if (not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            or not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)):
        raise AtlasReleaseBlocked("Invalid immutable release identity")
    mark("trusted-paths")
    preflight = preflight or load_operator(
        "atlas_release_preflight", "/usr/local/sbin/shadowops-identity-atlas-preflight")
    backup_operator = backup_operator or load_operator(
        "atlas_release_backup", "/usr/local/sbin/shadowops-identity-atlas-backup")
    preflight.trusted_paths()
    mark("atlas-marker")
    root_file(STATE / "atlas-active", private=True)
    root_file(ROOT / "atlas-compose.yaml")
    mark("backup-restore")
    require_atlas_restore_evidence(backup_operator.private_config(), STATE)
    mark("shared-host")
    check_shared()
    mark("live-container")
    previous, previous_sha = live_image(runner)
    if previous == digest:
        raise AtlasReleaseBlocked("No Atlas image change")
    mark("public-source")
    if public_release_sha(runner) != previous_sha:
        raise AtlasReleaseBlocked("Live public release differs from Atlas container")
    mark("candidate-config")
    require_isolated_config()
    mark("candidate-preflight")
    if preflight.execute(digest, source_sha, config_path=SNOOKER_CONFIG) != (
            "IDENTITY_ATLAS_PREFLIGHT_OK source_sha=" + source_sha + " digest=" + digest):
        raise AtlasReleaseBlocked("Candidate Atlas preflight not proven")
    compose = ["docker", "compose", "--project-directory", str(ROOT),
               "-f", str(ROOT / "atlas-compose.yaml")]
    for selected, phase in ((previous, "compose-previous"), (digest, "compose-candidate")):
        mark(phase)
        source = CONFIG if selected == previous else SNOOKER_CONFIG
        normalized = json.loads(runner(compose + ["config", "--format", "json"],
                                       digest=selected, config_source=source))
        validate_atlas_compose(normalized, selected, config_source=source)

    def activate(image):
        rollback = image == previous
        mark("rollback-activation" if rollback else "candidate-activation")
        if rollback and progress is not None:
            progress["rollback"] = "attempted"
        try:
            runner(compose + ["up", "--detach", "--no-deps", "--wait",
                              "--wait-timeout", "150", "--no-build", "--pull", "never",
                              "--force-recreate", "identity"], digest=image,
                   config_source=CONFIG if rollback else SNOOKER_CONFIG, timeout=195)
        except Exception:
            fail()
            if rollback and progress is not None:
                progress["rollback"] = "unverified"
            raise

    def verify(image):
        rollback = image == previous
        prefix = "rollback" if rollback else "candidate"
        try:
            mark(prefix + "-inspect")
            actual_digest, actual_sha = live_image(
                runner, config_source=CONFIG if rollback else SNOOKER_CONFIG)
            expected_sha = previous_sha if rollback else source_sha
            if actual_digest != image or actual_sha != expected_sha:
                fail()
                return False
            mark(prefix + "-public")
            if public_release_sha(runner) != expected_sha:
                fail()
                return False
            if not rollback:
                mark("candidate-audience")
                if not snooker_login_ready(runner):
                    fail()
                    return False
            if rollback and progress is not None:
                progress["rollback"] = "verified"
            return True
        except (AtlasReleaseBlocked, AtlasTransitionBlocked, OSError,
                ValueError, TypeError, KeyError, IndexError):
            fail()
            return False
        finally:
            if rollback and progress is not None and progress.get("rollback") != "verified":
                progress["rollback"] = "unverified"

    mark("transition-start")
    guarded_transition(previous, digest,
                       journal=journal or TransitionCheckpoint(STATE),
                       activate=activate, verify=verify)
    mark("complete")
    return "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + source_sha + " digest=" + digest


def main():
    progress = {"stage": "request", "rollback": "not-started"}
    try:
        if (os.geteuid() != 0 or len(sys.argv) != 4 or sys.argv[1] != "deploy"):
            raise AtlasReleaseBlocked("Invalid root operator request")
        progress["stage"] = "lock"
        # O_NOFOLLOW and exclusive flock prevent symlink and concurrent release tricks.
        fd = os.open(STATE / "deploy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077):
                raise AtlasReleaseBlocked("Untrusted release lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(update(sys.argv[2], sys.argv[3], progress=progress))
        finally:
            os.close(fd)
        return 0
    except Exception as exc:
        # Stage is a bounded enum; no Docker output, exception messages, secrets
        # or private journal contents are ever rendered to the caller.
        stage = progress.get("failure", progress.get("stage", "request"))
        stage = stage if stage in STAGES else "request"
        rollback = progress.get("rollback", "not-started")
        rollback = rollback if rollback in ROLLBACK_STATES else "not-started"
        kind = type(exc).__name__
        kind = kind if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,48}", kind) else "Error"
        print("IDENTITY_ATLAS_DEPLOY_BLOCKED type=" + kind
              + " stage=" + stage + " rollback=" + rollback, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
