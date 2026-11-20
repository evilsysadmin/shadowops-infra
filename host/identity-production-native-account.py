#!/usr/bin/env python3
"""One-time, offline-console native account enrollment in LIVE production Identity.

Only an already-running, digest-pinned isolated production container may receive
a password via anonymous stdin pipe. No new HTTP registration route, OCI, DNS,
Cloudflare, staging connection, image pull, or service restart. Never log secret.
"""
from __future__ import annotations

from contextlib import suppress
import getpass
import importlib.util
import os
import re
import subprocess
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_origin_operator", ROOT / "host/identity-production-origin.py"
)
origin_operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin_operator)
origin = origin_operator.origin

ALIAS = re.compile(r"[a-z][a-z0-9_]{2,31}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
CONFIRM = "PROVISION_ONE_NATIVE_PRODUCTION_ACCOUNT"
EXECUTABLE = "/app/identity-production"
LOG_LIMIT = 2048


class Refused(ValueError):
    pass


def _service_id(*, runner=subprocess.run):
    """Find ONE running Compose-owned production origin, not a user-chosen ID."""
    rows = origin_operator.project_container_status(runner=runner)
    origins = [row for row in rows if row["Service"] == origin_operator.SERVICE]
    if len(origins) != 1 or origins[0]["State"] != "running":
        raise Refused("exact running production origin required")
    others = [row for row in rows if row["Service"] != origin_operator.SERVICE]
    if any(row["Service"] != origin_operator.TUNNEL or row["State"] != "running"
           for row in others):
        raise Refused("ambiguous production project runtime")
    identifier = origin_operator.run(
        origin_operator.origin_compose_args("ps", "-q", origin_operator.SERVICE),
        runner=runner,
    )
    if not CONTAINER_ID.fullmatch(identifier):
        raise Refused("cannot prove one full production container ID")
    return identifier


def _inspect_container(container_id: str, expected_image: str, *, runner=subprocess.run):
    if not CONTAINER_ID.fullmatch(container_id) or not expected_image.startswith(origin_operator.IMAGE):
        raise Refused("unsafe production container ID or image")
    raw = origin_operator.run([
        "docker", "inspect", "--format",
        '{{.Config.Image}}|{{.Config.User}}|{{.State.Running}}|'
        '{{index .Config.Labels "com.docker.compose.project"}}|'
        '{{index .Config.Labels "com.docker.compose.service"}}|'
        '{{.HostConfig.ReadonlyRootfs}}',
        container_id,
    ], runner=runner)
    if raw.split("|") != [expected_image, "65532:65532", "true",
                           origin_operator.PROJECT, origin_operator.SERVICE, "true"]:
        raise Refused("running container differs from pinned production origin")


def admission(*, runner=subprocess.run, probe=origin.inspect):
    """Reprove the trusted image, actual container and TLS readiness."""
    sha, image = origin_operator.origin_admission(runner=runner)
    container = _service_id(runner=runner)
    _inspect_container(container, image, runner=runner)
    certificate = origin.ca_file(os.environ.get(origin.CA_ENV, ""))
    receipt = probe(certificate)
    if (receipt.get("tls") != "verified" or receipt.get("ready") != "yes" or
            receipt.get("jwks") != "ed25519-public" or
            receipt.get("registration") != "disabled" or
            receipt.get("foreign_host") != "denied"):
        raise Refused("production TLS / issuer / registration contract not ready")
    return {"sha": sha, "container": container, "image": image}


def password_bytes(read=getpass.getpass) -> bytearray:
    """Require confirmation, never echo or pass secret via flags/environ."""
    first = read("New production account password (minimum 15 characters): ")
    second = read("Repeat production account password: ")
    if not isinstance(first, str) or not isinstance(second, str) or first != second:
        raise Refused("password confirmation failed")
    try:
        raw = bytearray(first.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise Refused("invalid account password encoding") from None
    if not 15 <= len(first) <= 4096 or not 15 <= len(raw) <= 4096 or any(
        value in raw for value in (0, 10, 13)
    ):
        for i in range(len(raw)):
            raw[i] = 0
        raise Refused("invalid account password")
    return raw


def run_provision(container: str, alias: str, password: bytearray,
                  *, runner=subprocess.run) -> None:
    """Docker -i preserves a pipe; -t would turn stdin into a TTY and is forbidden."""
    if not CONTAINER_ID.fullmatch(container) or not ALIAS.fullmatch(alias):
        raise Refused("invalid trusted account target")
    if not isinstance(password, bytearray) or not 15 <= len(password) <= 4096:
        raise Refused("invalid secret input")
    # Do NOT print the password, command stderr/stdout or inspect Mongo content.
    command = [
        "docker", "exec", "-i", "--user", "65532:65532",
        container, EXECUTABLE, "provision-native-account", alias,
    ]
    try:
        # Separate newline is the Go CLI's strictly bounded pipe framing.
        supplied = bytes(password) + b"\n"
        result = runner(command, input=supplied, capture_output=True,
                        timeout=55, check=False)
        if result.returncode != 0:
            raise Refused("production account provisioning failed")
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("production account provisioning outcome unknown; inspect before retry") from None
    finally:
        for i in range(len(password)):
            password[i] = 0


def provision(alias: str, *, reader=getpass.getpass,
              runner=subprocess.run, probe=origin.inspect):
    if not ALIAS.fullmatch(alias):
        raise Refused("invalid alias: lowercase ASCII only")
    origin_operator.require_manual(CONFIRM)
    with origin_operator.exclusive():
        verified = admission(runner=runner, probe=probe)
        # Ask for secrets ONLY after confirming correct production target.
        secret = password_bytes(read=reader)
        try:
            # Repeat admission after the user typed; rotated/restarted containers
            # cannot inherit credentials from the earlier observation.
            if admission(runner=runner, probe=probe) != verified:
                raise Refused("production container changed during enrollment")
            run_provision(verified["container"], alias, secret, runner=runner)
        finally:
            for i in range(len(secret)):
                secret[i] = 0


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_NATIVE_ACCOUNT_PLAN scope=existing-production-origin "
              "registration=operator-only password=anonymous-pipe HTTP=no")
        return 0
    if len(argv) != 2 or argv[0] not in ("inspect", "create") or not ALIAS.fullmatch(argv[1]):
        print("Usage: identity-production-native-account.py plan|inspect ALIAS|create ALIAS",
              file=sys.stderr)
        return 2
    try:
        if argv[0] == "inspect":
            admission()
            print("IDENTITY_PRODUCTION_NATIVE_ACCOUNT_ADMITTED ready=yes "
                  "registration=closed account=NOT_CREATED")
        else:
            provision(argv[1])
            print("IDENTITY_PRODUCTION_NATIVE_ACCOUNT_CREATED "
                  "environment=production alias=" + argv[1] +
                  " registration=closed password=not-logged")
        return 0
    except Exception:
        # Captured Docker stderr may contain private configuration: never emit.
        print("IDENTITY_PRODUCTION_NATIVE_ACCOUNT_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
