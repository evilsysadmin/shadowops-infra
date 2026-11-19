#!/usr/bin/env python3
"""Read-only admission for the opt-in production Identity Cloudflare tunnel.

The named tunnel's JSON credentials are *never read*. No DNS, OCI, Cloudflare,
Mongo, Docker, container start, certificate issuance or secret creation.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import uuid
import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "compose.identity.production-tunnel.yaml"
HOST = "id.shadowops.dpdns.org"
CONFIG_TARGET = "/etc/cloudflared/config.yml"
CREDENTIAL_TARGET = "/run/secrets/identity-tunnel-credentials.json"
CA_TARGET = "/run/secrets/identity-tunnel-origin-ca.pem"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UID = 65532

class Refused(ValueError):
    pass

class StrictYAML(yaml.SafeLoader):
    """Reject ambiguous YAML that another parser could interpret differently."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent) or getattr(self.peek_event(), "anchor", None):
            raise Refused("YAML anchors and aliases are not admitted")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise Refused("YAML merge keys are not admitted")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in seen:
                raise Refused("duplicate or non-string YAML mapping key")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)

def strict_yaml(contents: str):
    try:
        return yaml.load(contents, Loader=StrictYAML)
    except yaml.YAMLError as exc:
        raise Refused("invalid or ambiguous YAML") from exc

def private_file(path: str, *, expected_uid: int = UID) -> Path:
    if not path or "\x00" in path:
        raise Refused("private file missing")
    target = Path(path)
    if not target.is_absolute() or target == Path("/"):
        raise Refused("private path must be absolute")
    try:
        for part in (target, *target.parents):
            if stat.S_ISLNK(os.lstat(part).st_mode):
                raise Refused("symlink in private path")
        info = os.lstat(target)
    except OSError as exc:
        raise Refused("private file unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or
            stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or
            not 1 <= info.st_size <= 131072):
        raise Refused("private file has unsafe owner, mode or size")
    return target

def validate_config(contents: str) -> None:
    if len(contents.encode("utf-8")) > 16384:
        raise Refused("tunnel config too large")
    try:
        data = strict_yaml(contents)
    except yaml.YAMLError as exc:
        raise Refused("invalid tunnel YAML") from exc
    if not isinstance(data, dict) or set(data) != {"tunnel", "credentials-file", "ingress"}:
        raise Refused("unexpected top-level tunnel configuration")
    try:
        tunnel_id = uuid.UUID(data["tunnel"])
    except (ValueError, AttributeError, TypeError) as exc:
        raise Refused("invalid tunnel UUID") from exc
    if str(tunnel_id) != data["tunnel"] or tunnel_id.version != 4:
        raise Refused("tunnel id must be canonical UUIDv4")
    if data["credentials-file"] != CREDENTIAL_TARGET:
        raise Refused("tunnel credentials must use private bind target")
    routes = data["ingress"]
    if not isinstance(routes, list) or len(routes) != 2:
        raise Refused("production tunnel requires exact host then deny-all")
    first, last = routes
    if not isinstance(first, dict) or set(first) != {"hostname", "service", "originRequest"}:
        raise Refused("untrusted hostname mapping")
    if first["hostname"] != HOST or first["service"] != "https://identity-production:9443":
        raise Refused("unexpected production route")
    if first["originRequest"] != {
        "originServerName": HOST,
        "httpHostHeader": HOST,
        "caPool": CA_TARGET,
    }:
        raise Refused("origin TLS SNI, host or CA mismatch")
    if last != {"service": "http_status:404"}:
        raise Refused("fallback must deny all unknown hostnames")

def validate_overlay() -> None:
    try:
        data = strict_yaml(OVERLAY.read_text(encoding="utf-8"))
        services, networks = data["services"], data["networks"]
        runtime, tunnel = services["identity-production"], services["identity-production-tunnel"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise Refused("production tunnel Compose missing") from exc
    image_token = "$" + "{IDENTITY_PRODUCTION_TUNNEL_DIGEST:?Pin cloudflared sha256 digest}"
    if (data.get("name") != "shadowops-identity-production" or
            set(services) != {"identity-production", "identity-production-tunnel"} or
            runtime != {"networks": ["identity-origin", "identity-mongo-egress"]} or
            tunnel.get("profiles") != ["production-tunnel"] or
            tunnel.get("image") != "cloudflare/cloudflared@" + image_token or
            tunnel.get("command") != ["tunnel", "--no-autoupdate", "--config", CONFIG_TARGET, "run"] or
            tunnel.get("user") != "65532:65532" or
            tunnel.get("read_only") is not True or
            tunnel.get("privileged") is not False or
            tunnel.get("cap_drop") != ["ALL"] or
            tunnel.get("security_opt") != ["no-new-privileges:true"] or
            tunnel.get("restart") != "no" or
            tunnel.get("networks") != ["identity-origin", "identity-tunnel-egress"] or
            tunnel.get("depends_on") != {"identity-production": {"condition": "service_started"}} or
            any(k in tunnel for k in ("ports", "network_mode", "environment", "env_file", "build", "entrypoint")) or
            tunnel.get("mem_limit") != "128m" or tunnel.get("pids_limit") != 64 or
            tunnel.get("cpus") != 0.25 or
            networks != {
                "identity-origin": {"name": "shadowops-identity-production-origin", "internal": True},
                "identity-mongo-egress": {"name": "shadowops-identity-production-mongo-egress"},
                "identity-tunnel-egress": {"name": "shadowops-identity-production-tunnel-egress"},
            }):
        raise Refused("production tunnel service or network contract changed")
    volumes = tunnel.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 3:
        raise Refused("unexpected tunnel mounts")
    expected = [
        ("$" + "{IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE:?Absolute operator-owned named tunnel config}", CONFIG_TARGET),
        ("$" + "{IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE:?Absolute private named tunnel credentials}", CREDENTIAL_TARGET),
        ("$" + "{IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE:?Absolute origin TLS CA certificate}", CA_TARGET),
    ]
    for entry, (source, target) in zip(volumes, expected):
        if entry != {"type": "bind", "source": source, "target": target,
                     "read_only": True, "bind": {"create_host_path": False}}:
            raise Refused("unsafe tunnel bind mount")

def validate(digest: str, config: str, credentials: str, ca: str,
             *, expected_uid: int = UID) -> None:
    if not IMAGE_RE.fullmatch(digest):
        raise Refused("cloudflared image must use immutable sha256 digest")
    files = [private_file(p, expected_uid=expected_uid) for p in (config, credentials, ca)]
    if len(set(files)) != 3:
        raise Refused("cannot reuse production tunnel secret material")
    # Reads ONLY the routing config and CA, NEVER the credentials JSON.
    validate_config(files[0].read_text(encoding="utf-8"))
    try:
        ssl.create_default_context(cafile=str(files[2]))
    except (ssl.SSLError, OSError) as exc:
        raise Refused("invalid origin CA certificate") from exc
    validate_overlay()

def main(argv: list[str]) -> int:
    if argv != ["inspect"]:
        print("Usage: identity_production_tunnel_preflight.py inspect", file=sys.stderr)
        return 2
    try:
        validate(os.environ.get("IDENTITY_PRODUCTION_TUNNEL_DIGEST", ""),
                 os.environ.get("IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE", ""),
                 os.environ.get("IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE", ""),
                 os.environ.get("IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE", ""))
    except (Refused, OSError, UnicodeError, TypeError):
        print("IDENTITY_PRODUCTION_TUNNEL_REFUSED", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_TUNNEL_PREFLIGHT_OK image=pinned origin=strict-TLS host=exact deploy=none")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
