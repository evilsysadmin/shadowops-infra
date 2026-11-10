"""Root-owned serialization lock shared by Atlas backup, preflight, canary, deploy.

Legacy .open("a") could create deploy.lock at 0644, which the release operator
correctly rejected. This module NEVER weakens permission checks or silently
repairs an existing lock. A separate explicit, narrowly scoped operation can
repair only the known empty 0644 legacy inode.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

DEFAULT_STATE = Path("/var/lib/shadowops/identity-staging")
NAME = "deploy.lock"


class AtlasLockBlocked(ValueError):
    pass


def _directory(state, uid=0):
    state = Path(state)
    for path in (state, *state.parents):
        meta = path.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != uid
                or meta.st_mode & 0o022):
            raise AtlasLockBlocked("Untrusted lock directory")
    if stat.S_IMODE(state.stat().st_mode) != 0o700:
        raise AtlasLockBlocked("Atlas lock directory must be private")


def _metadata(meta, uid=0, gid=0):
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
            or meta.st_gid != gid or meta.st_nlink != 1 or meta.st_size != 0):
        return "unsafe"
    # Exact mode, not merely group/world bits; no setuid/sticky/special modes.
    mode = stat.S_IMODE(meta.st_mode)
    if mode == 0o600:
        return "secure"
    if mode == 0o644:
        return "legacy-0644"
    return "unsafe"


def status(state=DEFAULT_STATE, uid=0, gid=0):
    """No file contents, no writes, no lock acquisition."""
    _directory(state, uid)
    try:
        meta = (Path(state) / NAME).lstat()
    except FileNotFoundError:
        return "missing"
    return _metadata(meta, uid, gid)


@contextmanager
def exclusive(state=DEFAULT_STATE, uid=0, gid=0):
    """Create only 0600; refuse existing unsafe/legacy inode, never truncate."""
    _directory(state, uid)
    fd = os.open(Path(state) / NAME,
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if _metadata(os.fstat(fd), uid, gid) != "secure":
            raise AtlasLockBlocked("Untrusted Atlas deploy lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def repair_legacy(state=DEFAULT_STATE, uid=0, gid=0):
    """Explicit operator-only repair, never auto-run by preflight or deploy.

    Only one empty, singly-linked, root-owned, root-group 0644 inode in the
    known private state directory may be tightened. No unlink or replacement.
    Must own exclusive flock to prevent racing running operations.
    """
    if os.geteuid() != 0:
        raise AtlasLockBlocked("Root required")
    _directory(state, uid)
    state = Path(state)
    # A pending transition is a separate incident. Do not touch its lock.
    try:
        (state / "atlas-deploy-pending.json").lstat()
    except FileNotFoundError:
        pass
    else:
        raise AtlasLockBlocked("Pending transition requires reconciliation")

    fd = os.open(state / NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        prior = _metadata(before, uid, gid)
        if prior not in ("secure", "legacy-0644"):
            raise AtlasLockBlocked("Unknown lock inode; manual review required")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        after = os.stat(state / NAME, follow_symlinks=False)
        if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or _metadata(os.fstat(fd), uid, gid) != prior):
            raise AtlasLockBlocked("Lock changed during inspection")
        if prior == "secure":
            return "already-secure"
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        if _metadata(os.fstat(fd), uid, gid) != "secure":
            raise AtlasLockBlocked("Lock repair not verified")
        return "repaired-legacy-0644"
    finally:
        os.close(fd)
