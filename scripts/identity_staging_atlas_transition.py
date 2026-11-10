"""Fail-closed building blocks for a future, separately approved Atlas Identity release.

No Docker command, network call, host mutation, credential read, or deployment
workflow is provided by this module. It validates a captured Docker inspect
record and owns a durable, minimal digest-only rollback checkpoint. Caller
must separately verify image provenance, Atlas backup and public exact SHA.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

PROJECT = "shadowops-identity-staging"
IMAGE = "ghcr.io/evilsysadmin/shadowops-identity@"
CONFIG = "/etc/shadowops/identity-staging/atlas-service.json"
SNOOKER_CONFIG = "/etc/shadowops/identity-staging/atlas-snooker-service.json"
ALLOWED_CONFIGS = frozenset({CONFIG, SNOOKER_CONFIG})
TARGET = "/run/secrets/identity-staging.json"
NETWORKS = frozenset({PROJECT + "-origin", PROJECT + "-atlas-egress"})
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")


class AtlasTransitionBlocked(ValueError):
    """Always use static error text, never raw Docker/host exception strings."""


def image_from_atlas_container(rows, config_source=CONFIG):
    """Prove a single healthy Atlas-bound Compose Identity and immutable image.

    Returns a digest only, not proof of valid signing or a safe rollback.
    Callers must independently admit that digest before using it.
    """
    if config_source not in ALLOWED_CONFIGS:
        raise AtlasTransitionBlocked("Untrusted Identity config source")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise AtlasTransitionBlocked("Ambiguous Identity container")
    row = rows[0]
    cfg = row.get("Config")
    state = row.get("State")
    host = row.get("HostConfig")
    nets = row.get("NetworkSettings")
    mounts = row.get("Mounts")
    if not all(isinstance(x, dict) for x in (cfg, state, host, nets)):
        raise AtlasTransitionBlocked("Incomplete Identity metadata")
    labels = cfg.get("Labels")
    image = cfg.get("Image")
    if (not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != PROJECT
            or labels.get("com.docker.compose.service") != "identity"
            or not isinstance(image, str) or not image.startswith(IMAGE)
            or not DIGEST.fullmatch(image.removeprefix(IMAGE))):
        raise AtlasTransitionBlocked("Untrusted Identity image or ownership")
    health = state.get("Health")
    if (state.get("Status") != "running" or not isinstance(health, dict)
            or health.get("Status") != "healthy"):
        raise AtlasTransitionBlocked("Identity is not healthy")
    if host.get("PortBindings") not in (None, {}):
        raise AtlasTransitionBlocked("Identity has unexpected host ports")
    attached = nets.get("Networks")
    if not isinstance(attached, dict) or set(attached) != NETWORKS:
        raise AtlasTransitionBlocked("Identity is not on isolated Atlas networks")
    if not isinstance(mounts, list) or len(mounts) > 16:
        raise AtlasTransitionBlocked("Ambiguous Identity mounts")
    candidates = [m for m in mounts if isinstance(m, dict)
                  and m.get("Destination") == TARGET]
    if (len(candidates) != 1 or candidates[0].get("Type") != "bind"
            or candidates[0].get("Source") != config_source
            or candidates[0].get("RW") is not False):
        raise AtlasTransitionBlocked("Identity does not bind Atlas config read-only")
    return image.removeprefix(IMAGE)


class TransitionCheckpoint:
    """One outstanding Atlas release at a time; never overwrite a pending attempt.

    Only fixed immutable digests are stored (no URLs, credentials or config).
    The root-owned 0700 directory and 0600 journal are checked on every use.
    """

    def __init__(self, directory: Path, *, expected_uid: int = 0):
        self.directory = Path(directory)
        self.path = self.directory / "atlas-deploy-pending.json"
        self.expected_uid = expected_uid

    def _trusted_directory(self):
        try:
            meta = self.directory.lstat()
        except OSError:
            raise AtlasTransitionBlocked("Missing trusted transition directory") from None
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != self.expected_uid
                or meta.st_mode & 0o077):
            raise AtlasTransitionBlocked("Unsafe transition directory")

    def _fsync_directory(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.open(self.directory, flags)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise AtlasTransitionBlocked("Transition directory sync failed") from None

    @staticmethod
    def _check_digests(previous, candidate):
        if (not all(isinstance(v, str) and DIGEST.fullmatch(v)
                    for v in (previous, candidate)) or previous == candidate):
            raise AtlasTransitionBlocked("Invalid Atlas update pair")

    def begin(self, previous, candidate):
        self._check_digests(previous, candidate)
        self._trusted_directory()
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
        except OSError:
            raise AtlasTransitionBlocked("Pending or unsafe Atlas transition") from None
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                json.dump({"previous": previous, "candidate": candidate},
                          stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            self._fsync_directory()
        except (OSError, TypeError, AtlasTransitionBlocked):
            # Journal remains in place to force operator reconciliation.
            raise AtlasTransitionBlocked("Atlas journal incomplete; operator review required") from None

    def clear(self, previous, candidate):
        self._check_digests(previous, candidate)
        self._trusted_directory()
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="ascii") as stream:
                meta = os.fstat(stream.fileno())
                if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != self.expected_uid
                        or meta.st_mode & 0o077 or meta.st_size > 256):
                    raise AtlasTransitionBlocked("Unsafe Atlas checkpoint")
                content = json.load(stream)
            if content != {"previous": previous, "candidate": candidate}:
                raise AtlasTransitionBlocked("Atlas checkpoint mismatch")
            self.path.unlink()
            self._fsync_directory()
        except (OSError, ValueError, TypeError):
            raise AtlasTransitionBlocked("Atlas checkpoint cannot be cleared") from None


def guarded_transition(previous, candidate, *, journal, activate, verify):
    """Callback-only transition; caller supplies *reviewed* fixed staging actions.

    A candidate is accepted only on literal True from an external verifier
    that must validate the live service's exact source SHA, digest and audience.
    Failure rolls back to the previously admitted image. Unverified rollback
    leaves a durable checkpoint and fails closed.
    """
    TransitionCheckpoint._check_digests(previous, candidate)
    journal.begin(previous, candidate)
    try:
        activate(candidate)
        if verify(candidate) is not True:
            raise AtlasTransitionBlocked("Candidate not proven")
    except Exception:
        try:
            activate(previous)
            if verify(previous) is not True:
                raise AtlasTransitionBlocked("Previous release not proven")
        except Exception:
            raise AtlasTransitionBlocked(
                "Atlas rollback unverified; checkpoint retained"
            ) from None
        journal.clear(previous, candidate)
        raise AtlasTransitionBlocked("Candidate failed; previous release verified") from None
    journal.clear(previous, candidate)
