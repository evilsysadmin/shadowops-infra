#!/usr/bin/env python3
"""Local workstation only: new production Mongo CA, TLS PEM and replica key.

Creates an all-new private directory under the operator's HOME. The offline
CA signing key is deliberately outside the three-file transfer bundle.
Never connects to A1, Docker, OCI, cloud, SSH or GitHub. Never overwrites.
"""
from __future__ import annotations

import base64
import getpass
import os
from pathlib import Path
import secrets
import ssl
import stat
import subprocess
import sys

ACK = "GENERATE_NEW_OFFLINE_PRODUCTION_MONGO_PKI"
NAMES = ("ca.pem", "mongo.pem", "replica.key")
CERT_DNS = ("identity-mongo-production", "localhost")
CERT_IP = "127.0.0.1"


class Refused(ValueError):
    pass


def run_openssl(*args: str, timeout=30) -> None:
    try:
        p = subprocess.run(["openssl", *args],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("native OpenSSL operation unavailable") from None
    if p.returncode != 0:
        raise Refused("native OpenSSL operation failed")


def passphrase_from_tty(*, prompt=getpass.getpass) -> bytes:
    """Two masked prompts, returned only to OpenSSL through anonymous stdin."""
    first = prompt("New OFFLINE CA encryption passphrase (>=32 bytes): ")
    repeated = prompt("Repeat OFFLINE CA encryption passphrase: ")
    if first != repeated or not isinstance(first, str):
        raise Refused("CA passphrase mismatch")
    try:
        raw = first.encode("utf-8")
    except UnicodeError:
        raise Refused("invalid CA passphrase") from None
    if (not 32 <= len(raw) <= 512 or
            b"\\x00" in raw or b"\\r" in raw or b"\\n" in raw):
        raise Refused("CA passphrase must be strong and one line")
    return raw


def run_openssl_secret(*args: str, ca_passphrase: bytes, timeout=30) -> None:
    """Pass CA unlock/encryption phrase only through OpenSSL's stdin pipe.

    No password on argv, environment, disk, stdout or stderr. The CA key
    itself is generated directly as encrypted PKCS#8 without a plaintext
    intermediate key file.
    """
    if (not isinstance(ca_passphrase, bytes) or
            not 32 <= len(ca_passphrase) <= 512 or
            b"\\n" in ca_passphrase or b"\\r" in ca_passphrase or
            b"\\x00" in ca_passphrase):
        raise Refused("unapproved CA passphrase")
    try:
        p = subprocess.run(
            ["openssl", *args], input=ca_passphrase + b"\\n",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("native encrypted OpenSSL unavailable") from None
    if p.returncode != 0:
        raise Refused("native encrypted OpenSSL operation failed")


def authorization(*, env=None, euid=None, stdin=None, stdout=None, prompt=input):
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if (euid == 0 or env.get("CI") or env.get("GITHUB_ACTIONS") or
            not stdin.isatty() or not stdout.isatty()):
        raise Refused("interactive non-root local workstation required")
    if prompt("Confirm creation of a NEW production CA and replica key: ").strip() != ACK:
        raise Refused("offline operator confirmation denied")


def output_path(raw: str, *, home=None, euid=None) -> Path:
    if not raw or "\x00" in raw or "\n" in raw:
        raise Refused("explicit output directory required")
    path = Path(raw).expanduser()
    home = Path.home() if home is None else Path(home)
    euid = os.geteuid() if euid is None else euid
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise Refused("absolute new directory required")
    try:
        home = home.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        mode = parent.stat()
        if (not parent.is_relative_to(home) or not stat.S_ISDIR(mode.st_mode)
                or mode.st_uid != euid or stat.S_IMODE(mode.st_mode) & 0o022):
            raise Refused("output must be within a private operator home tree")
        if path.exists() or path.is_symlink():
            raise Refused("output directory already exists")
    except OSError:
        raise Refused("invalid or missing output parent") from None
    return parent / path.name


def create_local_bundle(directory: Path, *, ca_passphrase: bytes) -> None:
    """Synthetic CI may call this in a disposable private directory.

    Actual CLI requires operator authorization *before* invoking this
    function, and is always denied in CI.
    """
    if not isinstance(ca_passphrase, bytes) or not 32 <= len(ca_passphrase) <= 512:
        raise Refused("strong CA encryption passphrase required")
    old_umask = os.umask(0o077)
    try:
        try:
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            offline = directory / "offline-ca-KEEP-LOCAL"
            transfer = directory / "transfer-THREE-FILES-ONLY"
            offline.mkdir(mode=0o700)
            transfer.mkdir(mode=0o700)
        except OSError:
            raise Refused("cannot create private output directory") from None

        ca_key = offline / "ca-private.key"
        ca_cert = transfer / "ca.pem"
        server_key = offline / "server-temp.key"
        csr = offline / "server-temp.csr"
        server_cert = offline / "server-temp.crt"
        ext = offline / "server-temp.ext"
        output = transfer / "mongo.pem"
        replica = transfer / "replica.key"

        # Key material created by native OpenSSL under umask 077; no output
        # containing a key is sent to a terminal or log.
        run_openssl_secret(
            "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-aes-256-cbc", "-pass", "stdin",
            "-out", str(ca_key), ca_passphrase=ca_passphrase,
        )
        run_openssl_secret(
            "req", "-new", "-x509", "-key", str(ca_key),
            "-passin", "stdin", "-days", "1825", "-sha256",
                    "-subj", "/CN=ShadowOps Identity Production Mongo CA",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-out", str(ca_cert), ca_passphrase=ca_passphrase)
        run_openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-out", str(server_key))
        run_openssl("req", "-new", "-key", str(server_key),
                    "-subj", "/CN=identity-mongo-production", "-out", str(csr))
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:identity-mongo-production,DNS:localhost,IP:127.0.0.1\n"
        )
        run_openssl_secret(
            "x509", "-req", "-in", str(csr),
            "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-passin", "stdin", "-set_serial", "0x" + secrets.token_hex(16),
                    "-days", "365", "-sha256", "-extfile", str(ext),
                    "-out", str(server_cert), ca_passphrase=ca_passphrase)

        # Certificate chain then matching private key, in the single Mongo
        # --tlsCertificateKeyFile. Exclusive file creation and mode 0600.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        with os.fdopen(fd, "wb") as writer:
            writer.write(server_cert.read_bytes())
            writer.write(server_key.read_bytes())
        fd = os.open(replica, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        with os.fdopen(fd, "wb") as writer:
            writer.write(base64.b64encode(secrets.token_bytes(384)) + b"\n")

        # Local synthetic crypto verification before any operator transfer.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(output))
        for dns in CERT_DNS:
            run_openssl("verify", "-CAfile", str(ca_cert),
                        "-purpose", "sslserver", "-verify_hostname", dns, str(output))
        run_openssl("verify", "-CAfile", str(ca_cert), "-purpose",
                    "sslserver", "-verify_ip", CERT_IP, str(output))
        run_openssl("x509", "-in", str(output), "-noout", "-checkend", "2592000")
        if {p.name for p in transfer.iterdir()} != set(NAMES):
            raise Refused("transfer directory contains unreviewed files")
        for path in (ca_key, *transfer.iterdir()):
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
                raise Refused("new private material has wrong mode")

        # The signing CA key must never exist in plaintext even temporarily.
        if not ca_key.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            raise Refused("offline signing CA is not encrypted PKCS#8")

        # Remove redundant ephemeral server material after the combined PEM
        # is successfully verified. CA private key remains in OFFLINE ONLY.
        for p in (server_key, csr, server_cert, ext):
            p.unlink()
    except (OSError, ssl.SSLError) as exc:
        # Retain directory 0700 on failure; never silently delete or print
        # private paths/contents. Operator cleans up securely after inspection.
        raise Refused("offline generation failed; inspect private directory") from None
    finally:
        os.umask(old_umask)


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_PKI_PLAN"
              " destination=local-private-home"
              " ca_private=encrypted-offline-only ca_duration=1825d"
              " leaf_duration=365d dns=production+localhost ip=127.0.0.1"
              " transfer=ca.pem+mongo.pem+replica.key"
              " overwrite=no remote=no root=no ci=no")
        return 0
    if len(argv) != 2 or argv[0] != "generate":
        print("Usage: identity_production_mongo_pki_generate.py plan|generate ABSOLUTE_NEW_DIRECTORY",
              file=sys.stderr)
        return 2
    try:
        authorization()
        dest = output_path(argv[1])
        ca_passphrase = passphrase_from_tty()
        create_local_bundle(dest, ca_passphrase=ca_passphrase)
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_PKI_REFUSED"
              " if-partial=inspect-private-local-directory", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_MONGO_PKI_CREATED"
          " ca_private=aes256-encrypted-offline-only transfer=three-private-files"
          " target=operator-selected-directory remote=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
