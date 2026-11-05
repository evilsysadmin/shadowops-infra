"""Validate the current Identity container before an Atlas-only update.

This module does not change containers or authorize an image. Its result is a
rollback image candidate, not proof that the public service can be restored.
"""
import json
import os
from pathlib import Path
import re
import stat

IMAGE = 'ghcr.io/evilsysadmin/shadowops-identity@'
CONFIG = '/etc/shadowops/identity-staging/atlas-service.json'
TARGET = '/run/secrets/identity-staging.json'
PROJECT = 'shadowops-identity-staging'


class TransitionError(ValueError):
    pass


def current_atlas_image(rows):
    """Accept exactly one healthy, project-owned Atlas Identity container."""
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise TransitionError('Ambiguous current Identity container')
    row = rows[0]
    labels = row.get('Config', {}).get('Labels') or {}
    image = row.get('Config', {}).get('Image')
    state = row.get('State', {})
    mounts = row.get('Mounts')
    bindings = row.get('HostConfig', {}).get('PortBindings')
    if (labels.get('com.docker.compose.project') != PROJECT
            or labels.get('com.docker.compose.service') != 'identity'
            or not isinstance(image, str)
            or not re.fullmatch(re.escape(IMAGE) + r'sha256:[a-f0-9]{64}', image)
            or state.get('Status') != 'running'
            or state.get('Health', {}).get('Status') != 'healthy'
            or bindings or not isinstance(mounts, list)):
        raise TransitionError('Unsafe current Identity container')
    configs = [m for m in mounts if isinstance(m, dict) and m.get('Destination') == TARGET]
    if len(configs) != 1 or configs[0].get('Source') != CONFIG or configs[0].get('RW') is not False:
        raise TransitionError('Current Identity is not using the Atlas configuration')
    return image.removeprefix(IMAGE)


class TransitionCheckpoint:
    """Durably record the previous image before replacing the live service.

    A leftover checkpoint blocks another transition until an operator has
    resolved the previous one. It contains image digests only, never secrets.
    """
    def __init__(self, directory, expected_uid=0):
        self.directory = Path(directory)
        self.path = self.directory / 'atlas-deploy-pending.json'
        self.expected_uid = expected_uid

    def _check_directory(self):
        meta = self.directory.lstat()
        if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != self.expected_uid or meta.st_mode & 0o077):
            raise TransitionError('Unsafe transition state directory')

    def begin(self, previous, candidate):
        self._check_directory()
        if any(not isinstance(v, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', v) for v in (previous, candidate)):
            raise TransitionError('Invalid transition image')
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as output:
                json.dump({'previous': previous, 'candidate': candidate}, output)
                output.flush()
                os.fsync(output.fileno())
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            raise TransitionError('Pending or unwritable transition checkpoint') from None

    def clear(self, previous, candidate):
        self._check_directory()
        try:
            meta = self.path.lstat()
            if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode)
                    or meta.st_uid != self.expected_uid or meta.st_mode & 0o077 or meta.st_size > 512):
                raise TransitionError('Unsafe transition checkpoint')
            value = json.loads(self.path.read_text())
            if value != {'previous': previous, 'candidate': candidate}:
                raise TransitionError('Transition checkpoint does not match')
            self.path.unlink()
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, ValueError, TypeError):
            raise TransitionError('Invalid transition checkpoint') from None


def transition(previous, candidate, checkpoint, activate, verify):
    """Run a staged update; leave evidence if rollback cannot be verified.

    The caller must perform image admission, backup checks and locking first.
    Activation and verification must be fixed staging-only operations.
    """
    checkpoint.begin(previous, candidate)
    try:
        activate(candidate)
        if not verify(candidate):
            raise TransitionError('Candidate verification failed')
    except Exception:
        try:
            activate(previous)
            if not verify(previous):
                raise TransitionError('Rollback verification failed')
        except Exception:
            raise TransitionError('Rollback unverified; checkpoint retained') from None
        checkpoint.clear(previous, candidate)
        raise TransitionError('Candidate failed; previous image restored') from None
    checkpoint.clear(previous, candidate)
