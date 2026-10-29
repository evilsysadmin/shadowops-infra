#!/usr/bin/python3 -I
"""Manually operated, staging-only installer for the CKA DRY-RUN systemd unit.

No API access, network setup, inference, service start or enablement.
Requires root-owned, clean, pinned source checkouts and an already installed
Python environment. Do not call from OCI Run Command or a GitHub workflow.
"""
import argparse
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile

INFRA = Path("/opt/shadowops-infra")
APP = Path("/opt/shadowops/cka-factory-staging")
SOURCE = APP / "source"
PYTHON = APP / "venv/bin/python"
WORKSPACE = Path("/var/lib/shadowops/cka-factory-staging")
UNIT_SOURCE = INFRA / "host/cka-factory-staging.service"
UNIT_DEST = Path("/etc/systemd/system/shadowops-cka-factory-staging.service")
USER = "shadowops-cka-factory"
SHA = re.compile(r"[0-9a-f]{40}\Z")
ACK = "INSTALL_CKA_DRY_RUN_STAGING_ONLY"


class InstallError(ValueError):
    pass


def trusted(path: Path, *, directory: bool = False) -> None:
    """Refuse symlinks and non-root-owned/group-writable source ancestry."""
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise InstallError("Trusted source contains a symlink")
        try:
            metadata = candidate.stat()
        except OSError:
            raise InstallError("Trusted source is missing") from None
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise InstallError("Trusted source must be root-owned and not writable")
        if candidate == path:
            kind = stat.S_ISDIR if directory else stat.S_ISREG
            if not kind(metadata.st_mode):
                raise InstallError("Trusted source has wrong file type")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("Trusted source ancestry is not a directory")


def command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, text=True, capture_output=True,
                                timeout=12, check=True)
    except (OSError, subprocess.SubprocessError):
        raise InstallError("Pinned source verification failed") from None
    if len(result.stdout) > 4096:
        raise InstallError("Unexpected source verification output")
    return result.stdout.strip()


def verify_checkout(path: Path, expected: str) -> None:
    trusted(path, directory=True)
    trusted(path / ".git", directory=True)
    if command(["git", "-C", str(path), "rev-parse", "--show-toplevel"]) != str(path):
        raise InstallError("Pinned checkout must be its own repository root")
    if command(["git", "-C", str(path), "rev-parse", "HEAD"]) != expected:
        raise InstallError("Pinned checkout SHA mismatch")
    # Untracked Python files can shadow the pinned application modules. They
    # must never survive the SHA gate, even when tracked files are pristine.
    if command(["git", "-C", str(path), "status", "--porcelain",
                "--untracked-files=all"]):
        raise InstallError("Pinned checkout contains modifications or untracked files")


def verify_venv_tree(venv: Path, *, expected_uid: int = 0, max_entries: int = 80000) -> int:
    """Reject writable, foreign-owned or redirected runtime dependencies.

    Inspect the entire venv before importing its Python code. Only the
    standard Linux venv lib64 -> lib compatibility symlink is accepted.
    This is filesystem integrity, NOT a signed dependency provenance proof.
    """
    if not venv.is_dir() or venv.is_symlink():
        raise InstallError("Python venv must be a real directory")
    entries = 0
    pending = [venv]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as listing:
                children = list(listing)
        except OSError:
            raise InstallError("Cannot inspect installed Python runtime") from None
        for child in children:
            entries += 1
            if entries > max_entries:
                raise InstallError("Python runtime exceeds inspection limit")
            try:
                meta = child.stat(follow_symlinks=False)
            except OSError:
                raise InstallError("Cannot inspect installed Python runtime") from None
            if child.is_symlink():
                # venv creates lib64 -> lib on some Linux distributions.
                if (Path(directory) == venv and child.name == "lib64"
                        and os.readlink(child.path) == "lib"):
                    continue
                raise InstallError("Python runtime contains unsafe symlink")
            if meta.st_uid != expected_uid or meta.st_mode & 0o022:
                raise InstallError("Python runtime has unsafe owner or write permissions")
            if stat.S_ISDIR(meta.st_mode):
                pending.append(Path(child.path))
            elif not stat.S_ISREG(meta.st_mode):
                raise InstallError("Python runtime contains unsafe special file")
    if entries == 0:
        raise InstallError("Python runtime is empty")
    return entries


def verify_runtime(expected_infra: str, expected_cka: str) -> bytes:
    if not SHA.fullmatch(expected_infra) or not SHA.fullmatch(expected_cka):
        raise InstallError("Two exact lowercase 40-hex SHAs are required")
    verify_checkout(INFRA, expected_infra)
    verify_checkout(SOURCE, expected_cka)
    trusted(APP, directory=True)
    trusted(APP / "venv", directory=True)
    trusted(APP / "venv/bin", directory=True)
    # Require a copied interpreter, not a symlink to an unverified executable.
    trusted(PYTHON)
    if not os.access(PYTHON, os.X_OK):
        raise InstallError("Pinned Python runtime is not executable")
    # The interpreter must be part of this venv, not an unrelated Python that
    # happens to import the pinned checkout through its global environment.
    verify_venv_tree(APP / "venv")
    python_prefix = command([str(PYTHON), "-I", "-c", "import sys; print(sys.prefix)"])
    if python_prefix != str(APP / "venv"):
        raise InstallError("Python interpreter is not using the staging venv")
    if command([str(PYTHON), "-I", "-m", "pip", "check"]) != "No broken requirements found.":
        raise InstallError("Python dependency requirements are inconsistent")
    # A root-owned read-only editable install is permitted only if it resolves
    # to the exact SHA-pinned CKA source tree (the catalog uses ROOT from here).
    resolved = command([str(PYTHON), "-I", "-c",
                        "from cka_sim.catalog import ROOT; print(ROOT)"])
    if resolved != str(SOURCE):
        raise InstallError("Installed CKA catalog does not resolve to pinned source")
    trusted(UNIT_SOURCE)
    content = UNIT_SOURCE.read_bytes()
    if (b"--execute" in content or b"EnvironmentFile=" in content
            or b"\n[Install]" in content
            or b"PrivateNetwork=yes" not in content
            or b"ProtectSystem=strict" not in content
            or b"ReadWritePaths=/var/lib/shadowops/cka-factory-staging" not in content):
        raise InstallError("CKA dry-run service policy changed unexpectedly")
    trusted(UNIT_DEST.parent, directory=True)
    trusted(WORKSPACE.parent, directory=True)
    for target in (UNIT_DEST, WORKSPACE):
        if target.is_symlink():
            raise InstallError("Unsafe staging destination symlink")
    if UNIT_DEST.exists():
        trusted(UNIT_DEST)
        if UNIT_DEST.read_bytes() != content:
            raise InstallError("Existing systemd unit differs; no overwrites allowed")
    return content


def installed_account():
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        try:
            grp.getgrnam(USER)
        except KeyError:
            return None
        raise InstallError("Service group exists without service user") from None
    if (user.pw_shell != "/usr/sbin/nologin"
            or user.pw_dir != "/nonexistent"
            or grp.getgrgid(user.pw_gid).gr_name != USER):
        raise InstallError("Existing service account is not isolated")
    return user


def verify_workspace(account) -> None:
    if WORKSPACE.is_symlink():
        raise InstallError("Workspace cannot be a symlink")
    if WORKSPACE.exists():
        metadata = WORKSPACE.stat()
        if (not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or account is None
                or (metadata.st_uid, metadata.st_gid) != (account.pw_uid, account.pw_gid)):
            raise InstallError("Existing staging workspace is unsafe")


def preflight(infra_sha: str, cka_sha: str) -> bytes:
    content = verify_runtime(infra_sha, cka_sha)
    verify_workspace(installed_account())
    return content


def install_unit_exclusive(content: bytes, destination: Path = UNIT_DEST) -> None:
    """Fully stage and sync the unit before atomically publishing it.

    os.link refuses to replace a file installed by another operation; even
    a failed/partial write cannot leave a truncated systemd unit behind.
    """
    fd, temporary = tempfile.mkstemp(prefix=".cka-factory-", dir=destination.parent)
    stage = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(stage, destination, follow_symlinks=False)
        except FileExistsError:
            raise InstallError("Existing staging unit cannot be overwritten") from None
    finally:
        stage.unlink(missing_ok=True)


def install(infra_sha: str, cka_sha: str, ack: str) -> None:
    if os.geteuid() != 0:
        raise InstallError("Root is required for manual staging installation")
    if ack != ACK:
        raise InstallError("Explicit staging dry-run confirmation is required")
    content = preflight(infra_sha, cka_sha)  # ALL checks before any mutation.
    account = installed_account()
    if account is None:
        command(["useradd", "--system", "--user-group", "--home-dir",
                 "/nonexistent", "--shell", "/usr/sbin/nologin", USER])
        account = installed_account()
        if account is None:
            raise InstallError("Could not provision isolated service account")
    if not WORKSPACE.exists():
        WORKSPACE.mkdir(mode=0o700)  # parent is preprovisioned; never create it
        os.chown(WORKSPACE, account.pw_uid, account.pw_gid)
        os.chmod(WORKSPACE, 0o700)
    verify_workspace(account)
    # Stage completely before publishing; never leave a partial systemd unit.
    if not UNIT_DEST.exists() and not UNIT_DEST.is_symlink():
        install_unit_exclusive(content, UNIT_DEST)
    elif UNIT_DEST.is_symlink() or UNIT_DEST.read_bytes() != content:
        raise InstallError("Unit changed during installation")
    print("CKA_STAGING_DRY_RUN_UNIT_INSTALLED_NOT_STARTED")
    print("Manual follow-up: systemctl daemon-reload then inspect unit; DO NOT enable a timer")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["preflight", "install"])
    parser.add_argument("infra_sha")
    parser.add_argument("cka_sha")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            if args.confirm:
                raise InstallError("Confirmation is not accepted for preflight")
            preflight(args.infra_sha, args.cka_sha)
            print("CKA_STAGING_INSTALL_PREFLIGHT_OK_NO_HOST_CHANGES")
        else:
            install(args.infra_sha, args.cka_sha, args.confirm)
    except InstallError as exc:
        print("CKA_STAGING_INSTALL_BLOCKED: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
