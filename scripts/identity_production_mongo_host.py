#!/usr/bin/env python3
"""Offline, read-only gate for the independent production Mongo host candidate.

No Docker start, no network, no secret-value output, and no chmod/chown.
CI checks the Compose contract with synthetic fixtures. Host inspect only
checks fixed local file metadata and CA parseability. Not a backup gate.
"""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import stat
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.identity.production-mongo.yaml"
SECRET_DIR = Path("/etc/shadowops/identity-production/mongo")
PROJECT = "shadowops-identity-production-mongo"
SERVICE = "identity-production-mongo"
REPLICA = "identity-production-rs"
IMAGE = "mongo@sha256:8bb4442761a63a8dda452744082cdac9644b429807eb977b42324a63cef59ca4"
VOLUME = "shadowops-identity-production-mongo-data"
NETWORK = "shadowops-identity-production-mongo-egress"


class Refused(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise Refused("duplicate or invalid YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent) or getattr(self.peek_event(), "anchor", None):
            raise Refused("YAML aliases or anchors forbidden")
        return super().compose_node(parent, index)


def validate_compose(text: str) -> None:
    if len(text.encode("utf-8")) > 16000:
        raise Refused("oversized compose")
    try:
        config = yaml.load(text, Loader=StrictLoader)
        if not isinstance(config, dict) or set(config) != {"name", "services", "volumes", "networks"}:
            raise Refused("foreign compose configuration")
        if config["name"] != PROJECT or set(config["services"]) != {SERVICE}:
            raise Refused("wrong project or service")
        db = config["services"][SERVICE]
        required = {
            "profiles", "image", "platform", "user", "entrypoint", "command",
            "init", "restart", "read_only", "privileged", "cap_drop",
            "security_opt", "pids_limit", "mem_limit", "cpus", "stop_grace_period",
            "volumes", "tmpfs", "networks", "healthcheck",
        }
        if not isinstance(db, dict) or set(db) != required:
            raise Refused("unreviewed service key")
        contract = {
            "profiles": ["production-mongo"],
            "image": IMAGE,
            "platform": "linux/arm64",
            "user": "999:999",
            "entrypoint": ["mongod"],
            "command": [
                "--replSet", REPLICA, "--bind_ip_all", "--wiredTigerCacheSizeGB", "0.25",
                "--keyFile", "/run/mongo/replica.key", "--tlsMode", "requireTLS",
                "--tlsCertificateKeyFile", "/run/mongo/mongo.pem", "--tlsCAFile",
                "/run/mongo/ca.pem", "--tlsAllowConnectionsWithoutCertificates",
            ],
            "init": True,
            "restart": "no",
            "read_only": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 128,
            "mem_limit": "768m",
            "cpus": 0.75,
            "stop_grace_period": "60s",
            "volumes": [
                {"type": "volume", "source": "identity-production-data", "target": "/data/db"},
                {"type": "bind", "source": str(SECRET_DIR), "target": "/run/mongo",
                 "read_only": True, "bind": {"create_host_path": False}},
            ],
            "tmpfs": ["/tmp:rw,noexec,nosuid,size=32m,uid=999,gid=999"],
            "networks": {"identity-mongo-egress": {"aliases": ["identity-mongo-production"]}},
            "healthcheck": {
                "test": ["CMD", "mongosh", "--quiet", "--norc", "--tls",
                         "--tlsCAFile", "/run/mongo/ca.pem",
                         "mongodb://127.0.0.1:27017/?directConnection=true",
                         "--eval", "if (!db.hello().isWritablePrimary) quit(1)"],
                "interval": "15s", "timeout": "5s", "start_period": "45s", "retries": 4,
            },
        }
        if db != contract:
            raise Refused("Mongo security contract changed")
        if config["volumes"] != {"identity-production-data": {"name": VOLUME}}:
            raise Refused("production volume contract changed")
        if config["networks"] != {"identity-mongo-egress": {"name": NETWORK, "internal": True}}:
            raise Refused("Mongo must remain on its isolated network")
    except (yaml.YAMLError, UnicodeError, KeyError, TypeError, AttributeError) as exc:
        raise Refused("untrusted compose") from exc


def inspect_private_files(*, path: Path = SECRET_DIR) -> None:
    """Metadata only; no private key/replica key read."""
    if path != SECRET_DIR:
        raise Refused("unreviewed path")
    try:
        for folder in (path, *path.parents):
            meta = folder.lstat()
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
                    stat.S_IMODE(meta.st_mode) & 0o022):
                raise Refused("untrusted directory")
        names = ("mongo.pem", "ca.pem", "replica.key")
        for name in names:
            info = (path / name).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 999 or
                    stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or
                    not 1 <= info.st_size <= 131072):
                raise Refused("untrusted Mongo material")
        # CA is public certificate material; secret keys remain unopened.
        ssl.create_default_context(cafile=str(path / "ca.pem"))
    except (OSError, ssl.SSLError) as exc:
        raise Refused("Mongo TLS prerequisites unavailable") from exc


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_HOST_PLAN state=not-deployed"
              " image=pinned-arm64 project=isolated volume=dedicated"
              " network=internal auth=keyfile tls=required"
              " backups=not-configured start=operator-only")
        return 0
    if argv != ["inspect"]:
        print("Usage: identity_production_mongo_host.py plan|inspect", file=sys.stderr)
        return 2
    try:
        validate_compose(COMPOSE.read_text(encoding="utf-8"))
        inspect_private_files()
    except (Refused, OSError, yaml.YAMLError):
        print("IDENTITY_PRODUCTION_MONGO_HOST_REFUSED", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_MONGO_HOST_INSPECT_OK"
          " files=private compose=isolated"
          " mongo=not-verified backups=not-verified deploy=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
