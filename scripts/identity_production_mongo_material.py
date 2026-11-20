#!/usr/bin/env python3
"""Root-only read-only cryptographic gate for production Mongo TLS/keyFile.

Uses fixed paths and names: cannot be redirected to a staging PKI. The
certificate's corresponding private key and the replica key are read only
into process memory for verification; their values never enter argv, env,
output, GitHub or network. Does not create secrets, Docker, or OCI objects.
"""
from __future__ import annotations

import base64
import binascii
import importlib.util
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_host", HERE / "identity_production_mongo_host.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_MATERIAL_REFUSED")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

CA = host.SECRET_DIR / "ca.pem"
CERT_KEY = host.SECRET_DIR / "mongo.pem"
REPLICA_KEY = host.SECRET_DIR / "replica.key"
DNS = ("identity-mongo-production", "localhost")
IP = "127.0.0.1"
MIN_LIFETIME_SECONDS = 30 * 24 * 60 * 60
FORBIDDEN_CA_KEYS = (
    "ca.key", "ca-private.key", "ca.key.offline", "ca-private.pem",
    "ca-key.pem",
)


class Refused(ValueError):
    pass


def verify_run(args: list[str], *, runner=subprocess.run) -> None:
    """No shell, no inherited stdin, opaque subprocess error output."""
    try:
        result = runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("TLS verification unavailable") from None
    if result.returncode != 0:
        raise Refused("TLS verification refused")


def verify_replica_key() -> None:
    # A replica key is a secret. Check content only in memory; never log it.
    try:
        with REPLICA_KEY.open("rb") as reader:
            content = reader.read(2049)
    except OSError:
        raise Refused("replica key not readable") from None
    if len(content) > 2048 or not content:
        raise Refused("invalid replica key size")
    if not re.fullmatch(rb"[A-Za-z0-9+/= \t\r\n]+", content):
        raise Refused("replica key contains unexpected bytes")
    encoded = re.sub(rb"[ \t\r\n]", b"", content)
    if not (128 <= len(encoded) <= 1024):
        raise Refused("replica key outside approved size")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise Refused("invalid replica key encoding") from None
    if not (96 <= len(decoded) <= 768) or len(set(decoded)) < 16:
        raise Refused("replica key too weak")


def verify_material(*, euid=None, env=None, runner=subprocess.run) -> None:
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid
    if euid != 0 or env.get("CI") or env.get("GITHUB_ACTIONS"):
        raise Refused("manual root host only")
    host.validate_compose(host.COMPOSE.read_text(encoding="utf-8"))
    host.inspect_private_files()

    # A1 may hold only the server private key, never the signing CA key.
    for name in FORBIDDEN_CA_KEYS:
        if (host.SECRET_DIR / name).exists() or (host.SECRET_DIR / name).is_symlink():
            raise Refused("offline signing CA key must not be installed on A1")

    # Verify the server certificate matches its own private key; opens in
    # memory but never logs the key (SSLContext raises only generic errors).
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_KEY))
    except (OSError, ssl.SSLError):
        raise Refused("server key/certificate pair invalid") from None

    base = ["openssl", "verify", "-CAfile", str(CA), "-purpose", "sslserver"]
    for name in DNS:
        verify_run([*base, "-verify_hostname", name, str(CERT_KEY)], runner=runner)
    verify_run([*base, "-verify_ip", IP, str(CERT_KEY)], runner=runner)
    for file in (CA, CERT_KEY):
        verify_run(
            ["openssl", "x509", "-in", str(file), "-noout",
             "-checkend", str(MIN_LIFETIME_SECONDS)],
            runner=runner,
        )
    verify_replica_key()


def main(args: list[str]) -> int:
    if args == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_MATERIAL_PLAN"
              " path=fixed-production-only"
              " tls=CA-signature+DNS+IP+matching-private-key"
              " lifetime=min-30d replica=base64-entropy"
              " ca-private-key=off-host required=root"
              " inspection=read-only secrets=never-printed")
        return 0
    if args != ["verify"]:
        print("Usage: identity_production_mongo_material.py plan|verify",
              file=sys.stderr)
        return 2
    try:
        verify_material()
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_MATERIAL_REFUSED", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_MONGO_MATERIAL_OK"
          " tls=signed-DNS-IP key=matched replica=valid"
          " ca-signing-key=off-host"
          " mongo=not-checked backup=not-verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
