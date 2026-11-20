#!/usr/bin/env python3
"""Operator-only Mongo backup: dump stream -> age ciphertext -> OCI Object Storage.

No plaintext archive on disk, no passwords in process arguments, no
Mongo/OCI/Cloudflare mutation except an explicitly enabled remote object PUT.
No automatic retention/deletions or production restore path.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

import identity_production_mongo_host as host

CONFIG_DIR = Path("/etc/shadowops/identity-production")
BACKUP_DIR = Path("/var/lib/shadowops-identity-production/backup-staging")
RECIPIENTS = CONFIG_DIR / "backup-recipients.txt"
MONGO_CONFIG = host.SECRET_DIR / "backup-tools.yml"
LOCK = Path("/run/lock/shadowops-identity-production-backup.lock")
ENABLE = "UPLOAD_ENCRYPTED_PRODUCTION_MONGO_TO_OCI"
MAX_CIPHER_BYTES = 4 * 1024**3
MIN_FREE = 8 * 1024**3
OBJECT_PREFIX = "shadowops/identity/production/mongo/"
LABELS = ("com.docker.compose.project=" + host.PROJECT,
          "com.docker.compose.service=" + host.SERVICE)


class Refused(ValueError):
    pass


def local_file(path: Path, owner: int, modes: tuple[int, ...]) -> None:
    if not path.is_absolute():
        raise Refused("private path must be absolute")
    try:
        for parent in path.parents:
            meta = parent.lstat()
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
                    stat.S_IMODE(meta.st_mode) & 0o022):
                raise Refused("unsafe parent")
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != owner or
                stat.S_IMODE(meta.st_mode) not in modes or
                not 1 <= meta.st_size <= 131072):
            raise Refused("unsafe file")
    except OSError as exc:
        raise Refused("operator file missing") from exc


def inspect_local(env, *, euid=None, resolve=shutil.which) -> tuple[str, str]:
    if env.get("CI") or env.get("GITHUB_ACTIONS"):
        raise Refused("CI is not a backup operator")
    if (os.geteuid() if euid is None else euid) != 0:
        raise Refused("root operator required")
    bucket = env.get("IDENTITY_PRODUCTION_BACKUP_BUCKET", "")
    namespace = env.get("IDENTITY_PRODUCTION_BACKUP_NAMESPACE", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", bucket) or not re.fullmatch(
            r"[A-Za-z0-9_-]{3,64}", namespace):
        raise Refused("operator bucket and namespace must be explicit")
    for tool in ("docker", "age", "oci"):
        if not resolve(tool):
            raise Refused("required native backup utility unavailable")
    host.validate_compose(host.COMPOSE.read_text(encoding="utf-8"))
    host.inspect_private_files()
    local_file(RECIPIENTS, 0, (0o400, 0o600))
    local_file(MONGO_CONFIG, 999, (0o400, 0o600))
    try:
        for path in (BACKUP_DIR, *BACKUP_DIR.parents):
            meta = path.lstat()
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
                    stat.S_IMODE(meta.st_mode) & 0o022):
                raise Refused("unsafe backup directory")
        if stat.S_IMODE(BACKUP_DIR.stat().st_mode) != 0o700:
            raise Refused("backup staging must be root-only")
        if shutil.disk_usage(BACKUP_DIR).free < MIN_FREE:
            raise Refused("insufficient disk reserve for encrypted backup")
    except OSError as exc:
        raise Refused("backup staging unavailable") from exc
    return namespace, bucket


def run_json(args: list[str], *, limit=131072, timeout=30) -> object:
    try:
        # Uploads are allowed a longer bounded interval than lightweight
        # Docker inspection and OCI HEAD requests.
        p = subprocess.run(args, check=False, capture_output=True, timeout=timeout)
        if p.returncode or len(p.stdout) > limit:
            raise Refused("verified command failed")
        return json.loads(p.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise Refused("verified command unavailable") from exc


def live_mongo_container() -> str:
    """Inspect the exact one healthy Compose Mongo; never touch staging."""
    ids = run_json_no_format()
    if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
        raise Refused("one exact production Mongo required")
    container_id = ids[0]
    data = run_json(["docker", "inspect", "--format", "{{json .}}", container_id])
    try:
        config, runtime, state = data["Config"], data["HostConfig"], data["State"]
        mounts = {m["Destination"]: m for m in data["Mounts"]}
        labels = config["Labels"]
        expected_networks = {host.NETWORK}
        if not (labels["com.docker.compose.project"] == host.PROJECT and
                labels["com.docker.compose.service"] == host.SERVICE and
                state["Running"] is True and
                state["Health"]["Status"] == "healthy" and
                config["Image"] == host.IMAGE and config["User"] == "999:999" and
                runtime["ReadonlyRootfs"] is True and
                runtime["Privileged"] is False and
                not runtime.get("PortBindings") and
                set(data["NetworkSettings"]["Networks"]) == expected_networks and
                mounts["/data/db"]["Name"] == host.VOLUME and
                mounts["/data/db"]["Type"] == "volume" and
                mounts["/run/mongo"]["Source"] == str(host.SECRET_DIR) and
                mounts["/run/mongo"]["RW"] is False):
            raise Refused("unexpected Mongo runtime")
    except (KeyError, TypeError, AttributeError):
        raise Refused("untrusted Mongo runtime") from None
    return container_id


def run_json_no_format() -> list[str]:
    args = ["docker", "ps", "--all"]
    for label in LABELS:
        args += ["--filter", "label=" + label]
    args += ["--format", "{{.ID}}"]
    try:
        p = subprocess.run(args, capture_output=True, timeout=15)
        if p.returncode or len(p.stdout) > 512:
            raise Refused("Mongo inventory unavailable")
        return p.stdout.decode("ascii").split()
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise Refused("Mongo inventory unavailable") from exc


def dump_args(container_id: str) -> list[str]:
    # Mongo Database Tools --config holds the account URI and password inside
    # the already read-only Mongo container; no secret crosses argv or env.
    return ["docker", "exec", "-i", container_id, "mongodump",
            "--config", "/run/mongo/backup-tools.yml", "--ssl",
            "--sslCAFile", "/run/mongo/ca.pem",
            "--archive", "--gzip", "--oplog"]


def put_args(namespace: str, bucket: str, key: str, path: Path) -> list[str]:
    return ["oci", "--auth", "instance_principal", "os", "object", "put",
            "--namespace-name", namespace, "--bucket-name", bucket,
            "--name", key, "--file", str(path),
            "--no-overwrite", "--verify-checksum"]


def head_args(namespace: str, bucket: str, key: str) -> list[str]:
    return ["oci", "--auth", "instance_principal", "os", "object", "head",
            "--namespace-name", namespace, "--bucket-name", bucket, "--name", key]


@contextmanager
def single_writer():
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
            raise Refused("backup lock not owned by root")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("backup already running") from None
        yield
    finally:
        os.close(fd)


def encrypted_dump(container_id: str, output: Path) -> None:
    """Stream plaintext only between processes; persist ciphertext alone."""
    dump = None
    crypt = None
    try:
        with output.open("wb") as encrypted:
            dump = subprocess.Popen(dump_args(container_id), stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, close_fds=True)
            try:
                crypt = subprocess.Popen(["age", "-R", str(RECIPIENTS)],
                                         stdin=dump.stdout, stdout=encrypted,
                                         stderr=subprocess.DEVNULL, close_fds=True)
            finally:
                dump.stdout.close()
            crypt_rc = crypt.wait(timeout=1200)
            dump_rc = dump.wait(timeout=1200)
        if dump_rc or crypt_rc:
            raise Refused("Mongo dump or encryption failed")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("encrypted backup stream failed") from exc
    finally:
        for process in (crypt, dump):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()


def upload_verified(namespace: str, bucket: str, key: str, path: Path) -> None:
    response = run_json(put_args(namespace, bucket, key, path), timeout=900)
    # --no-overwrite can return a non-upload informational response.
    if not isinstance(response, dict) or not response.get("etag"):
        raise Refused("object PUT was not confirmed")
    head = run_json(head_args(namespace, bucket, key))
    if (not isinstance(head, dict) or
            int(head.get("content-length", -1)) != path.stat().st_size or
            not head.get("etag")):
        raise Refused("remote ciphertext size not confirmed")


def backup(env=None) -> str:
    env = os.environ if env is None else env
    if env.get("IDENTITY_PRODUCTION_BACKUP_ENABLE") != ENABLE:
        raise Refused("explicit operator backup enable required")
    namespace, bucket = inspect_local(env)
    with single_writer():
        container = live_mongo_container()
        now = datetime.now(timezone.utc)
        name = now.strftime("%Y/%m/%d/%Y%m%dT%H%M%SZ-") + secrets.token_hex(16) + ".archive.gz.age"
        key = OBJECT_PREFIX + name
        # No plaintext dump ever lands in local storage.
        fd, temp = tempfile.mkstemp(prefix=".backup-", suffix=".age", dir=BACKUP_DIR)
        os.close(fd)
        output = Path(temp)
        try:
            encrypted_dump(container, output)
            size = output.stat().st_size
            if size < 128 or size > MAX_CIPHER_BYTES:
                raise Refused("ciphertext size outside quota")
            upload_verified(namespace, bucket, key, output)
            output.unlink()
            return key
        except Exception:
            # Keep only encrypted material after any upload failure, for
            # explicit human recovery; never log its path or contents.
            raise


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_BACKUP_PLAN source=isolated-mongo"
              " dump=full-oplog encryption=age-before-disk"
              " remote=oci-object-storage overwrite=deny"
              " restore=drill-required cleanup=no-remote-delete")
        return 0
    if argv not in (["inspect"], ["backup"]):
        print("Usage: identity_production_mongo_backup.py plan|inspect|backup", file=sys.stderr)
        return 2
    try:
        if argv == ["inspect"]:
            inspect_local(os.environ)
            print("IDENTITY_PRODUCTION_MONGO_BACKUP_INSPECT_OK"
                  " materials=present remote=not-probed restore=not-proven")
        else:
            key = backup()
            print("IDENTITY_PRODUCTION_MONGO_BACKUP_UPLOADED object=" + key +
                  " checksum=verified restore=not-proven")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_BACKUP_REFUSED"
              " encrypted-local-artifact=check-root-only-staging", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
