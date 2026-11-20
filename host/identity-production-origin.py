#!/usr/bin/env python3
"""Operator-only first production Identity origin launch, fail closed by default.

Stage 1 ONLY: starts/stops the private localhost Identity *origin*, never the
Cloudflare tunnel. No Github Actions, Kubernetes, OCI, DNS or Vault mutations.
Credentials are consumed only by Docker's readonly mounts; no bundle is read.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_production_compose_preflight as runtime
import identity_production_tunnel_preflight as tunnel
import identity_production_origin_probe as origin

PROJECT = "shadowops-identity-production"
MONGO_NETWORK = "shadowops-identity-production-mongo-egress"
MONGO_OWNER = "shadowops-identity-production-mongo"
MONGO_CONTAINER = "shadowops-identity-production-mongo-identity-production-mongo-1"
ORIGIN_CONTAINER = "shadowops-identity-production-identity-production-1"
SERVICE = "identity-production"
TUNNEL = "identity-production-tunnel"
LOCK = Path("/run/lock/shadowops-identity-production-origin.lock")
IMAGE = "ghcr.io/evilsysadmin/shadowops-identity-production-candidate@"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
CONFIRM_START = "START_LOOPBACK_PRODUCTION_IDENTITY_ONLY"
CONFIRM_STOP = "STOP_LOOPBACK_PRODUCTION_IDENTITY_ONLY"
BASE = ROOT / "compose.identity.production.yaml"
OVERLAY = ROOT / "compose.identity.production-tunnel.yaml"
ORIGIN_OVERLAY = ROOT / "compose.identity.production-origin.yaml"


class Refused(ValueError):
    pass


def env_contract(environ=os.environ):
    """Check operator artifacts; do not open production bundle or tunnel JSON."""
    if environ.get("CI") or environ.get("GITHUB_ACTIONS"):
        raise Refused("CI cannot access production operator actions")
    digest = environ.get("IDENTITY_PRODUCTION_IMAGE_DIGEST", "")
    sha = environ.get("IDENTITY_PRODUCTION_SOURCE_SHA", "")
    if not SOURCE_SHA.fullmatch(sha):
        raise Refused("immutable release source SHA required")
    runtime.validate(digest, environ.get("IDENTITY_PRODUCTION_BUNDLE_FILE", ""))
    tunnel.validate(
        environ.get("IDENTITY_PRODUCTION_TUNNEL_DIGEST", ""),
        environ.get("IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE", ""),
        environ.get("IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE", ""),
        environ.get("IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE", ""),
    )
    operator_ca = origin.ca_file(environ.get(origin.CA_ENV, ""))
    # Single source of trust: host probe and tunnel use the *same* CA bytes.
    # This certificate is public information; no credentials are read.
    tunnel_ca = Path(environ["IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE"])
    if operator_ca.read_bytes() != tunnel_ca.read_bytes():
        raise Refused("local origin probe CA differs from tunnel origin CA")
    return sha, IMAGE + digest


def origin_env_contract(environ=os.environ):
    """No Cloudflare materials at all are required to start the private origin."""
    if environ.get("CI") or environ.get("GITHUB_ACTIONS"):
        raise Refused("CI cannot access production operator actions")
    digest = environ.get("IDENTITY_PRODUCTION_IMAGE_DIGEST", "")
    sha = environ.get("IDENTITY_PRODUCTION_SOURCE_SHA", "")
    if not SOURCE_SHA.fullmatch(sha):
        raise Refused("immutable release source SHA required")
    runtime.validate(digest, environ.get("IDENTITY_PRODUCTION_BUNDLE_FILE", ""))
    origin.ca_file(environ.get(origin.CA_ENV, ""))
    return sha, IMAGE + digest


def origin_compose_args(*args):
    return [
        "docker", "compose", "-f", str(BASE), "-f", str(ORIGIN_OVERLAY),
        "--profile", "production", *args,
    ]


def compose_args(*args):
    return [
        "docker", "compose", "-f", str(BASE), "-f", str(OVERLAY),
        "--profile", "production", "--profile", "production-tunnel",
        *args,
    ]


def run(args, *, runner=subprocess.run):
    try:
        response = runner(
            args, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("fixed local Docker operation unavailable") from None
    if (response.returncode != 0 or
            not isinstance(response.stdout, str) or len(response.stdout) > 131072):
        # Docker logs may contain private host paths / configuration; never emit.
        raise Refused("fixed local Docker operation denied")
    return response.stdout.strip()


def _check_origin_fields(origin_service, image, require):
    require("origin-image", origin_service["image"] == image)
    require("origin-command", origin_service["command"] == ["serve-ready"])
    require("origin-user", origin_service["user"] == "65532:65532")
    require("origin-isolation", (
        origin_service.get("read_only") is True and
        origin_service.get("privileged", False) is False and
        origin_service["restart"] == "no" and
        origin_service["cap_drop"] == ["ALL"] and
        origin_service["security_opt"] == ["no-new-privileges:true"]
    ))
    require("loopback-port", origin_service["ports"] == [{
        "mode": "ingress", "target": 9443, "published": "19443",
        "host_ip": "127.0.0.1", "protocol": "tcp",
    }])
    require("origin-networks", set(origin_service["networks"]) ==
            {"identity-origin", "identity-mongo-egress"})
    require("origin-environment", origin_service["environment"] == {
        "IDENTITY_PRODUCTION_CONFIG_FILE": "/run/secrets/identity-production.json",
        "IDENTITY_INTERNAL_PORT": "9443",
    })
    require("origin-private-volume", (
        len(origin_service["volumes"]) == 1 and
        origin_service["volumes"][0]["target"] == "/run/secrets/identity-production.json" and
        origin_service["volumes"][0]["read_only"] is True and
        origin_service["volumes"][0].get("bind", {}).get("create_host_path", False) is False
    ))

def check_compose_config(raw: str, image: str, tunnel_digest: str) -> None:
    """Validate rendered Compose; errors expose only bounded fixed field names."""
    try:
        obj = json.loads(raw)
        def require(label, ok):
            if not ok:
                raise Refused("rendered production Compose rejected: " + label)

        require("project", obj["name"] == PROJECT)
        require("service-set", set(obj["services"]) == {SERVICE, TUNNEL})
        origin_service = obj["services"][SERVICE]
        proxy = obj["services"][TUNNEL]

        _check_origin_fields(origin_service, image, require)
        require("tunnel-image", proxy["image"] ==
                "cloudflare/cloudflared@" + tunnel_digest)
        require("tunnel-disabled", proxy["restart"] == "no" and not proxy.get("ports"))
        require("tunnel-segregation",
                set(proxy["networks"]) == {"identity-origin", "identity-tunnel-egress"})
        require("private-origin-network", obj["networks"]["identity-origin"].get("internal") is True)
        mongo = obj["networks"].get("identity-mongo-egress")
        require("mongo-named-network",
                isinstance(mongo, dict) and mongo.get("name") == MONGO_NETWORK and
                mongo.get("external") is not False and mongo.get("internal") is not True)
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise Refused("invalid production Compose structure") from None



def check_origin_compose_config(raw: str, image: str) -> None:
    """Origin-only stage has no tunnel service, credentials or public egress."""
    try:
        obj = json.loads(raw)
        def require(label, ok):
            if not ok:
                raise Refused("origin-only Compose rejected: " + label)
        require("project", obj["name"] == PROJECT)
        require("only-origin-service", set(obj["services"]) == {SERVICE})
        _check_origin_fields(obj["services"][SERVICE], image, require)
        require("only-private-and-mongo-networks",
                set(obj["networks"]) == {"identity-origin", "identity-mongo-egress"})
        require("private-origin-network",
                obj["networks"]["identity-origin"].get("internal") is True and
                obj["networks"]["identity-origin"].get("name") ==
                    "shadowops-identity-production-origin")
        mongo = obj["networks"]["identity-mongo-egress"]
        require("mongo-named-network",
                isinstance(mongo, dict) and mongo.get("name") == MONGO_NETWORK and
                mongo.get("external") is not False and mongo.get("internal") is not True)
    except (TypeError, KeyError, json.JSONDecodeError):
        raise Refused("invalid origin-only Compose structure") from None


def parse_ps(raw: str) -> list[dict]:
    if not raw.strip():
        return []
    try:
        # Docker Compose supports both a JSON array and newline-delimited JSON.
        parsed = json.loads(raw) if raw.lstrip().startswith("[") else [
            json.loads(line) for line in raw.splitlines() if line.strip()
        ]
        if not isinstance(parsed, list) or not all(isinstance(x, dict) for x in parsed):
            raise Refused("unrecognized compose status")
        for item in parsed:
            if item.get("Service") not in (SERVICE, TUNNEL) or item.get("Project", PROJECT) != PROJECT:
                raise Refused("unknown production service detected")
        return parsed
    except (ValueError, TypeError, KeyError) as exc:
        raise Refused("unrecognized compose status") from None


def container_status(*, runner=subprocess.run):
    return parse_ps(run(compose_args("ps", "-a", "--format", "json"), runner=runner))


def project_container_status(*, runner=subprocess.run):
    """Enumerate ALL containers of our exact Compose project, including orphans.

    A narrow origin-only Compose ps can hide a running tunnel as an orphan;
    Docker's project label is used instead so a stop never misses it.
    """
    raw = run([
        "docker", "ps", "--all",
        "--filter", "label=com.docker.compose.project=" + PROJECT,
        "--format", '{{.Label "com.docker.compose.service"}}|{{.State}}',
    ], runner=runner)
    rows = []
    for line in raw.splitlines():
        parts = line.split("|")
        if (len(parts) != 2 or parts[0] not in {SERVICE, TUNNEL} or
                parts[1] not in {"created", "running", "exited", "restarting", "paused", "dead"} or
                any(x["Service"] == parts[0] for x in rows)):
            raise Refused("ambiguous project-owned production container")
        rows.append({"Service": parts[0], "State": parts[1], "Project": PROJECT})
    return rows


def origin_overlay_mongo_external() -> None:
    """Check the source YAML: Docker Compose may omit 'external' from config JSON."""
    try:
        obj = tunnel.strict_yaml(ORIGIN_OVERLAY.read_text(encoding="utf-8"))
        if obj["networks"]["identity-mongo-egress"] != {
            "name": MONGO_NETWORK, "external": True,
        }:
            raise Refused("origin may only join pre-existing production Mongo network")
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("unsafe origin Mongo network declaration") from None


def mongo_network_admission(*, runner=subprocess.run) -> None:
    """Read-only Docker inspection: reject staging, rogue network and attachments.

    Identity must join the private network created by the dedicated Mongo
    production Compose project. It must never create/adopt a same-name bridge.
    """
    raw = run([
        "docker", "network", "inspect", "--format", "{{json .}}", MONGO_NETWORK
    ], runner=runner)
    try:
        network = json.loads(raw)
        if (not isinstance(network, dict) or
                network.get("Name") != MONGO_NETWORK or
                network.get("Driver") != "bridge" or
                network.get("Internal") is not True or
                not isinstance(network.get("Labels"), dict) or
                network["Labels"].get("com.docker.compose.project") != MONGO_OWNER or
                network["Labels"].get("com.docker.compose.network") != "identity-mongo-egress"):
            raise Refused("untrusted production Mongo network")
        attached = network["Containers"]
        if not isinstance(attached, dict) or not attached:
            raise Refused("production Mongo network has no owner")
        names = [value.get("Name") for value in attached.values()]
        if (len(names) != len(set(names)) or MONGO_CONTAINER not in names or
                set(names) - {MONGO_CONTAINER, ORIGIN_CONTAINER}):
            raise Refused("unexpected Mongo network participant")
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        raise Refused("invalid production Mongo network inventory") from None


def image_revision(image: str, *, runner=subprocess.run):
    rev = run([
        "docker", "image", "inspect", image,
        "--format", '{{ index .Config.Labels "org.opencontainers.image.revision" }}',
    ], runner=runner)
    if not SOURCE_SHA.fullmatch(rev):
        raise Refused("image source SHA label missing")
    return rev


def occupied(port=19443):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        return probe.connect_ex(("127.0.0.1", port)) == 0


@contextmanager
def exclusive(path=LOCK):
    if path.is_symlink():
        raise Refused("operator lock symlink")
    with open(path, "a+b") as handle:
        if handle.fileno() < 0:
            raise Refused("no operator lock")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("another production origin operator is active") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def admission(*, runner=subprocess.run):
    sha, image = env_contract()
    normalized = run(compose_args("config", "--format", "json"), runner=runner)
    check_compose_config(
        normalized, image, os.environ["IDENTITY_PRODUCTION_TUNNEL_DIGEST"]
    )
    if image_revision(image, runner=runner) != sha:
        raise Refused("image digest does not match expected source commit")
    mongo_network_admission(runner=runner)
    return sha, image


def origin_admission(*, runner=subprocess.run):
    """Stage 1 checks only its own image/bundle/CA and rendered network model."""
    sha, image = origin_env_contract()
    origin_overlay_mongo_external()
    normalized = run(origin_compose_args("config", "--format", "json"), runner=runner)
    check_origin_compose_config(normalized, image)
    if image_revision(image, runner=runner) != sha:
        raise Refused("image digest does not match expected source commit")
    mongo_network_admission(runner=runner)
    return sha, image


def require_manual(acknowledgement: str):
    if (os.geteuid() != 0 or os.environ.get("CI") or
            os.environ.get("GITHUB_ACTIONS") or not sys.stdin.isatty()):
        raise Refused("manual root-owned operator terminal required")
    if input("Confirm scope: ").strip() != acknowledgement:
        raise Refused("operator did not authorize exact action")


def start_origin(*, runner=subprocess.run, inspect=origin.inspect):
    require_manual(CONFIRM_START)
    with exclusive():
        origin_admission(runner=runner)
        existing = project_container_status(runner=runner)
        if existing or occupied():
            raise Refused("origin already present or reserved loopback port occupied")
        started = False
        try:
            started = True  # A failed up can leave an orphaned partial service.
            run(origin_compose_args(
                "up", "--detach", "--no-deps", "--no-build",
                "--pull", "never", SERVICE,
            ), runner=runner)
            after = project_container_status(runner=runner)
            if (len(after) != 1 or after[0]["Service"] != SERVICE or
                    after[0].get("State", "").lower() != "running"):
                raise Refused("unexpected service started instead of isolated origin")
            ca = origin.ca_file(os.environ.get(origin.CA_ENV, ""))
            # Bounded readiness window; never starts the tunnel.
            for index in range(10):
                try:
                    receipt = inspect(ca)
                    if receipt.get("tls") != "verified" or receipt.get("ready") != "yes":
                        raise Refused("production HTTPS receipt not healthy")
                    return
                except Exception:
                    if index == 9:
                        raise Refused("origin did not pass verified TLS admission") from None
                    time.sleep(2)
        except Exception:
            if started:
                try:
                    run(origin_compose_args("stop", "--timeout", "10", SERVICE), runner=runner)
                except Refused:
                    raise Refused("origin unhealthy; scoped rollback ALSO failed") from None
            raise Refused("origin start refused; scoped service stopped") from None


def stop_origin(*, runner=subprocess.run):
    require_manual(CONFIRM_STOP)
    with exclusive():
        origin_admission(runner=runner)
        existing = project_container_status(runner=runner)
        if any(row["Service"] == TUNNEL and row.get("State", "").lower() == "running"
               for row in existing):
            raise Refused("tunnel running: refusing to stop origin independently")
        targets = [x for x in existing if x["Service"] == SERVICE]
        if len(targets) != 1:
            raise Refused("expected one known production origin to stop")
        run(origin_compose_args("stop", "--timeout", "10", SERVICE), runner=runner)


def main(args: list[str]):
    if args == ["plan"]:
        print("IDENTITY_PRODUCTION_ORIGIN_PLAN no-credentials no-deploy start=manual stop=manual tunnel=never")
        return 0
    if args not in (["inspect"], ["start-origin"], ["stop-origin"]):
        print("Usage: identity-production-origin.py plan|inspect|start-origin|stop-origin", file=sys.stderr)
        return 2
    try:
        if args == ["inspect"]:
            origin_admission()
            print("IDENTITY_PRODUCTION_ORIGIN_ADMITTED image=sha-pinned policy=private ready=not-probed deploy=none")
        elif args == ["start-origin"]:
            start_origin()
            print("IDENTITY_PRODUCTION_ORIGIN_STARTED tls=verified ready=yes tunnel=not-started")
        else:
            stop_origin()
            print("IDENTITY_PRODUCTION_ORIGIN_STOPPED service=origin tunnel=untouched")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_ORIGIN_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
