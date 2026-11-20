#!/usr/bin/env python3
"""L14-only exact three-file Mongo production PKI upload over Cloudflare SSH.

This never transfers offline-ca-KEEP-LOCAL or a signing CA key. No remote
commands, sudo, deletion, stage creation, Docker, OCI or Identity activation.
The A1 root-only host installer remains authoritative after transfer.
"""
from __future__ import annotations

import base64
import binascii
import importlib.util
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oci_a1_ssh", HERE / "oci_a1_ssh.py")
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_PKI_UPLOAD_REFUSED")
a1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a1)

NAMES = ("ca.pem", "mongo.pem", "replica.key")
TRANSFER = "transfer-THREE-FILES-ONLY"
OFFLINE = "offline-ca-KEEP-LOCAL"
DEST = "/home/ubuntu/shadowops-mongo-pki-stage/"
ACK = "UPLOAD_THREE_PRODUCTION_MONGO_PKI_FILES_ONLY"
# Read-only, static remote probe. Do NOT allow rsync to create a world-
# traversable directory if the authorized ubuntu staging was never created.
REMOTE_PROBE = """import os, stat, sys
p = '/home/ubuntu/shadowops-mongo-pki-stage'
parent = os.lstat('/home/ubuntu')
s = os.lstat(p)
if not (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 1001 and
        stat.S_IMODE(parent.st_mode) & 0o022 == 0 and
        stat.S_ISDIR(s.st_mode) and s.st_uid == 1001 and
        stat.S_IMODE(s.st_mode) == 0o700 and
        not os.listdir(p)):
    sys.exit(21)
print('EMPTY_PRIVATE_STAGE')
"""
MAX_BYTES = {"ca.pem": 131072, "mongo.pem": 131072, "replica.key": 2048}


class Refused(ValueError):
    pass


def private_directory(path: Path, *, uid: int, mode: int = 0o700) -> None:
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or
            stat.S_IMODE(st.st_mode) != mode):
        raise Refused("not a private local PKI directory")


def local_package(env: dict[str, str], *, uid=None, home=None) -> list[Path]:
    uid = os.geteuid() if uid is None else uid
    home = Path.home() if home is None else Path(home)
    raw = env.get("MONGO_PKI_OUTPUT_DIR", "")
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise Refused("explicit private PKI directory required")
    folder = Path(raw).expanduser()
    if not folder.is_absolute():
        raise Refused("absolute private PKI path required")
    try:
        resolved_home = home.resolve(strict=True)
        # No symlink segments anywhere inside HOME.
        candidate = folder
        while candidate != resolved_home:
            if candidate.is_symlink():
                raise Refused("PKI source cannot contain symlinks")
            if candidate == candidate.parent:
                raise Refused("PKI must be within HOME")
            candidate = candidate.parent
        if not folder.resolve(strict=True).is_relative_to(resolved_home):
            raise Refused("PKI must be within HOME")
        private_directory(folder, uid=uid)
        private_directory(folder / TRANSFER, uid=uid)
        private_directory(folder / OFFLINE, uid=uid)
        offline = folder / OFFLINE
        if set(x.name for x in offline.iterdir()) != {"ca-private.key"}:
            raise Refused("unexpected offline CA content")
        ca_key = offline / "ca-private.key"
        ca_meta = ca_key.lstat()
        if (not stat.S_ISREG(ca_meta.st_mode) or ca_meta.st_uid != uid or
                ca_meta.st_nlink != 1 or stat.S_IMODE(ca_meta.st_mode) != 0o600):
            raise Refused("offline CA key unsafe")
        transfer = folder / TRANSFER
        if set(p.name for p in transfer.iterdir()) != set(NAMES):
            raise Refused("transfer bundle not exactly three files")
        result = []
        for name in NAMES:
            file = transfer / name
            meta = file.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or
                    meta.st_uid != uid or stat.S_IMODE(meta.st_mode) != 0o600 or
                    not 1 <= meta.st_size <= MAX_BYTES[name]):
                raise Refused("unexpected transfer file metadata")
            result.append(file)
        return result
    except OSError:
        raise Refused("local private PKI package unavailable") from None


def check_crypto(files: list[Path]) -> None:
    if len(files) != 3 or tuple(x.name for x in files) != NAMES:
        raise Refused("untrusted package")
    ca, cert, replica = files
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert))
        data = replica.read_bytes()
        clean = re.sub(rb"\s", b"", data)
        decoded = base64.b64decode(clean, validate=True)
        if not (96 <= len(decoded) <= 768 and len(set(decoded)) >= 16):
            raise Refused("weak Mongo replica key")
    except (OSError, ssl.SSLError, binascii.Error, ValueError):
        raise Refused("invalid local Mongo PKI") from None
    base = ["openssl", "verify", "-CAfile", str(ca), "-purpose", "sslserver"]
    commands = [
        [*base, "-verify_hostname", name, str(cert)]
        for name in ("identity-mongo-production", "localhost")
    ] + [
        [*base, "-verify_ip", "127.0.0.1", str(cert)],
        *[["openssl", "x509", "-in", str(file), "-noout", "-checkend", "2592000"]
          for file in (ca, cert)],
    ]
    for command in commands:
        try:
            run = subprocess.run(command, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=15, check=False)
            if run.returncode:
                raise Refused("invalid local Mongo TLS chain or SAN")
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("native TLS verification unavailable") from None


def rsync_args(rsync: str, ssh: str, cloudflared: str,
               host: str, user: str, key: str, files: list[Path]) -> list[str]:
    if len(files) != 3 or tuple(p.name for p in files) != NAMES:
        raise Refused("only the approved three-file bundle may be uploaded")
    ssh_cmd = a1.command(cloudflared, ssh, host, user, key)[:-1]
    return [
        rsync, "--archive", "--no-owner", "--no-group",
        "--chmod=F600", "--ignore-existing",
        "--no-links", "--no-devices", "--no-specials",
        "--quiet", "-e", shlex.join(ssh_cmd),
        "--", *(str(file) for file in files),
        user + "@" + host + ":" + DEST,
    ]


def remote_stage_probe(ssh: str, cloudflared: str, host: str,
                       user: str, key: str, *, runner=subprocess.run) -> None:
    args = a1.command(cloudflared, ssh, host, user, key) + [
        "python3 -I -c " + shlex.quote(REMOTE_PROBE)
    ]
    try:
        response = runner(args, stdin=None, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=False, timeout=35)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("remote private staging not verified") from None
    if response.returncode != 0 or response.stdout.strip() != b"EMPTY_PRIVATE_STAGE":
        raise Refused("remote staging must be empty, private and owned by ubuntu")


def require_workstation(env: dict[str, str], *, euid=None,
                        stdin=None, stdout=None, prompt=input) -> None:
    euid = os.geteuid() if euid is None else euid
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if (euid == 0 or env.get("CI") or env.get("GITHUB_ACTIONS") or
            platform.machine() not in ("x86_64", "aarch64") or
            not stdin.isatty() or not stdout.isatty()):
        raise Refused("interactive non-root workstation required")
    if prompt("Approve upload of exactly three Mongo PKI files: ").strip() != ACK:
        raise Refused("operator declined PKI upload")


def main(argv: list[str], *, env=None, runner=subprocess.run) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_PKI_UPLOAD_PLAN"
              " source=private-L14-transfer-only"
              " target=canonical-Cloudflare-A1"
              " files=three-exact ca-private=never"
              " overwrite=deny stage=must-preexist"
              " manual=rootless-tty-ack")
        return 0
    if argv not in (["check"], ["upload"]):
        print("Usage: identity_production_mongo_pki_upload.py plan|check|upload",
              file=sys.stderr)
        return 2
    env = os.environ if env is None else env
    try:
        if env.get("CI") or env.get("GITHUB_ACTIONS"):
            raise Refused("CI is prohibited")
        if argv == ["upload"]:
            require_workstation(env)
        files = local_package(env)
        check_crypto(files)
        host, user, key = a1.operator_settings(env)
        cloudflared, ssh, rsync = (shutil.which(name) for name in
                                  ("cloudflared", "ssh", "rsync"))
        if not cloudflared or not ssh or not rsync:
            raise Refused("local cloudflared/ssh/rsync required")
        a1.check_edge_tls(host)
        if argv == ["check"]:
            print("IDENTITY_PRODUCTION_MONGO_PKI_UPLOAD_CHECK_OK"
                  " local=valid edge=tls"
                  " remote_staging=not-inspected")
            return 0
        remote_stage_probe(ssh, cloudflared, host, user, key, runner=runner)
        args = rsync_args(rsync, ssh, cloudflared, host, user, key, files)
        result = runner(args, stdin=None, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=False, timeout=300)
        if result.returncode != 0:
            raise Refused("SSH transfer failed")
        print("IDENTITY_PRODUCTION_MONGO_PKI_UPLOAD_REQUEST_FINISHED"
              " files=three-only overwrite=deny"
              " remote_state=requires-A1-inspect")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_PKI_UPLOAD_REFUSED"
              " remote_state=unverified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
