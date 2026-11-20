#!/usr/bin/env python3
"""One-shot manual installation of EXACTLY three Mongo production PKI files.

No SSH, cloud, OCI, staging mutation, Docker start, or implicit overwrites.
The operator only accepts /home/ubuntu/shadowops-mongo-pki-stage and the
fixed production Mongo path. The offline CA signing key must stay on L14.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import platform
import pwd
import socket
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_start", HERE / "identity-production-mongo-start.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_PKI_INSTALL_REFUSED")
start = importlib.util.module_from_spec(spec)
spec.loader.exec_module(start)
host, material = start.host, start.material

STAGE = Path("/home/ubuntu/shadowops-mongo-pki-stage")
TARGET = host.SECRET_DIR
NAMES = ("ca.pem", "mongo.pem", "replica.key")
ACK = "INSTALL_NEW_PRODUCTION_MONGO_PKI_THREE_FILES_ONLY"
MAX_BYTES = {"ca.pem": 131072, "mongo.pem": 131072, "replica.key": 2048}


class Refused(ValueError):
    pass


def require_operator(*, mutation: bool, env=None, euid=None, stdin=None,
                     stdout=None, hostname=None, machine=None, prompt=input) -> None:
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    hostname = socket.gethostname() if hostname is None else hostname
    machine = platform.machine() if machine is None else machine
    if (euid != 0 or env.get("CI") or env.get("GITHUB_ACTIONS") or
            hostname != "chessbackend" or machine != "aarch64"):
        raise Refused("not the authorized root A1 host")
    if mutation and (not stdin.isatty() or not stdout.isatty() or
                     prompt("Confirm exact three-file Mongo PKI installation: ").strip() != ACK):
        raise Refused("manual operator confirmation required")


def safe_directory(path: Path, *, owner: int | None = None,
                   exact_mode: int | None = None) -> None:
    try:
        st = path.lstat()
    except OSError:
        raise Refused("required directory missing") from None
    if (not stat.S_ISDIR(st.st_mode) or
            (owner is not None and st.st_uid != owner) or
            (exact_mode is not None and stat.S_IMODE(st.st_mode) != exact_mode) or
            stat.S_IMODE(st.st_mode) & 0o022):
        raise Refused("directory is not private and trustworthy")


def absent(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise Refused("refusing to adopt or overwrite production material")


def read_staging(*, stage: Path = STAGE, operator_uid: int = 1001) -> dict[str, bytes]:
    """Use directory-relative O_NOFOLLOW descriptors to reject any alias/race.

    The expected fixed staging path is owned by the unprivileged operator.
    No user-supplied paths or extra files are accepted.
    """
    safe_directory(stage.parent, owner=operator_uid)
    safe_directory(stage, owner=operator_uid, exact_mode=0o700)
    try:
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused("staging directory could not be pinned") from None
    try:
        info = os.fstat(fd)
        if (info.st_uid != operator_uid or
                not stat.S_ISDIR(info.st_mode) or
                stat.S_IMODE(info.st_mode) != 0o700 or
                set(os.listdir(fd)) != set(NAMES)):
            raise Refused("staging contains unapproved files or private CA")
        result = {}
        for name in NAMES:
            try:
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                  os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                raise Refused("staged file unavailable") from None
            try:
                info = os.fstat(file_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != operator_uid or
                        info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                        not 1 <= info.st_size <= MAX_BYTES[name]):
                    raise Refused("staged material has unsafe metadata")
                data = bytearray()
                while len(data) <= MAX_BYTES[name]:
                    block = os.read(file_fd, min(65536, MAX_BYTES[name] + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                if len(data) != info.st_size:
                    raise Refused("staged file changed during inspection")
                result[name] = bytes(data)
            finally:
                os.close(file_fd)
        return result
    finally:
        os.close(fd)


def validate_namespace(*, target: Path = TARGET) -> None:
    # The only mutable host path is the fixed production PKI destination.
    if target == TARGET:
        for existing in (Path("/"), Path("/etc")):
            safe_directory(existing, owner=0)
    for part in (target.parents[1], target.parent):
        if part.exists() or part.is_symlink():
            safe_directory(part, owner=0)
    absent(target)


def preflight() -> dict[str, bytes]:
    require_operator(mutation=False)
    if pwd.getpwnam("ubuntu").pw_uid != 1001:
        raise Refused("unexpected host operator UID")
    host.validate_compose(host.COMPOSE.read_text(encoding="utf-8"))
    validate_namespace()
    payload = read_staging()
    material.verify_crypto(
        STAGE / "ca.pem", STAGE / "mongo.pem", STAGE / "replica.key",
    )
    # Detect a partial rsync/upload between cryptographic verification
    # and the bytes copied into the root-owned directory.
    if payload != read_staging():
        raise Refused("staging changed during cryptographic inspection")
    start.ensure_empty()
    return payload


def new_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    absent(path)
    os.mkdir(path, 0o700)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def write_new_files(target: Path, payload: dict[str, bytes], *,
                    file_uid: int = 999, file_gid: int = 999) -> None:
    """Narrow mutation after the authorized, read-only preflight.

    The destination is created exclusively. Failure leaves a sealed,
    root-only partial install for manual investigation, never overwrites.
    """
    if set(payload) != set(NAMES):
        raise Refused("unapproved payload")
    absent(target)
    old_umask = os.umask(0o077)
    try:
        new_directory(target, uid=0 if os.geteuid() == 0 else os.geteuid(),
                      gid=file_gid, mode=0o700)
        for name in NAMES:
            file_path = target / name
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as writer:
                writer.write(payload[name])
                writer.flush()
                os.fsync(writer.fileno())
                os.fchown(writer.fileno(), file_uid, file_gid)
                os.fchmod(writer.fileno(), 0o400)
    finally:
        os.umask(old_umask)


def install() -> None:
    require_operator(mutation=True)
    with start.single_operator():
        payload = preflight()
        # No preexisting destination ever gets changed or adopted. The
        # parent paths may be provisioned only if they are missing.
        namespace = TARGET.parents[1]
        parent = TARGET.parent
        if not namespace.exists() and not namespace.is_symlink():
            new_directory(namespace, uid=0, gid=0, mode=0o755)
        if not parent.exists() and not parent.is_symlink():
            new_directory(parent, uid=0, gid=999, mode=0o710)
        validate_namespace()
        write_new_files(TARGET, payload)
        # Check the installed material itself before allowing container UID
        # 999 to traverse the bind-mounted PKI directory.
        material.verify_material()
        os.chmod(TARGET, 0o710)
        host.inspect_private_files()


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_PKI_INSTALL_PLAN"
              " source=fixed-ubuntu-private-stage files=exactly-three"
              " destination=fixed-production-only overwrite=never"
              " ca-private=off-host verification=cryptographic"
              " mutation=root-tty-ack docker=start-never")
        return 0
    if argv not in (["inspect"], ["install"]):
        print("Usage: identity-production-mongo-pki-install.py plan|inspect|install",
              file=sys.stderr)
        return 2
    try:
        if argv == ["inspect"]:
            preflight()
            print("IDENTITY_PRODUCTION_MONGO_PKI_INSTALL_INSPECT_OK"
                  " staged=three-files tls=verified"
                  " existing-resources=none mutation=none")
        else:
            install()
            print("IDENTITY_PRODUCTION_MONGO_PKI_INSTALLED"
                  " files=three uid=999 mode=0400"
                  " mongodb=not-started backups=not-proven")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_PKI_INSTALL_REFUSED"
              " if-partial=do-not-retry-review-root-only-destination",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
