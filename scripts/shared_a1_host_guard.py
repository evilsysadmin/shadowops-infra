#!/usr/bin/env python3
"""Fail-closed Docker collision gate for the EXISTING shared OCI Ampere A1.

Observes all containers; never modifies Docker and never echoes its output.
Chronicles baseline and authenticated staging share :18081 and must never
coexist. Chess Studio uses separate projects and remains entirely untouched.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Callable

PROJECT_API = "shadowops-chronicles-staging"
PROJECT_BASELINE = "shadowops-chronicles"
PROJECT_WEB = "shadowops-chronicles-web-staging"
PORT_OWNERS = {18081: (PROJECT_API, "chronicles-api"),
               18082: (PROJECT_WEB, "chronicles-web")}
# The API project may run the API and its own Cloudflare Tunnel connector
# (which publishes no host port); nothing else.
API_SERVICES = frozenset({"chronicles-api", "chronicles-tunnel"})
MAX_BYTES = 512_000
MAPPING = re.compile(r"^(?P<host>.+):(?P<port>[0-9]+)->(?P<target>[0-9]+)/(tcp|udp)$")
LABEL = re.compile(r"(?:^|,)com[.]docker[.]compose[.](project|service)=([^,]+)")


class SharedHostError(ValueError):
    pass


def _compose_labels(value: object) -> tuple[str, str]:
    if not isinstance(value, str):
        raise SharedHostError("Docker container labels are malformed")
    found: dict[str, str] = {}
    for name, item in LABEL.findall(value):
        if name in found:
            raise SharedHostError("Duplicate Compose identity labels")
        found[name] = item
    return found.get("project", ""), found.get("service", "")


def inspect_container_rows(stdout: str) -> None:
    """Reject competing Compose projects and ANY foreign publisher on reserved ports."""
    if len(stdout.encode("utf-8")) > MAX_BYTES:
        raise SharedHostError("Docker inventory exceeds safe size")
    api_counts: dict[str, int] = {}
    web_count = 0
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise SharedHostError("Docker inventory contains invalid JSON") from None
        if not isinstance(row, dict) or not all(
            isinstance(row.get(key), str) for key in ("Names", "Labels", "Ports")
        ):
            raise SharedHostError("Docker container metadata is incomplete")
        project, service = _compose_labels(row["Labels"])
        if project == PROJECT_BASELINE:
            raise SharedHostError("Legacy Chronicles baseline project conflicts with staging")
        if project == PROJECT_API:
            if service not in API_SERVICES:
                raise SharedHostError("Unexpected service inside Chronicles staging project")
            api_counts[service] = api_counts.get(service, 0) + 1
            if api_counts[service] > 1:
                raise SharedHostError("Ambiguous duplicate Chronicles staging containers")
        if project == PROJECT_WEB:
            if service != "chronicles-web":
                raise SharedHostError("Unexpected service inside Chronicles staging web project")
            web_count += 1
            if web_count > 1:
                raise SharedHostError("Ambiguous duplicate Chronicles staging web containers")
        for fragment in row["Ports"].split(","):
            fragment = fragment.strip()
            if "->" not in fragment:
                continue
            match = MAPPING.fullmatch(fragment)
            if not match:
                raise SharedHostError("Unexpected Docker published-port format")
            port = int(match.group("port"))
            if port not in PORT_OWNERS:
                continue
            owner_project, owner_service = PORT_OWNERS[port]
            if (project, service) != (owner_project, owner_service):
                raise SharedHostError(f"Port {port} belongs to another service")
            if match.group("host") != "127.0.0.1":
                raise SharedHostError(f"Port {port} must be bound to loopback only")


# A stopped container can reserve a Docker host port without a listener or
# a visible 'docker ps -a' Ports entry. Inspect configured bindings explicitly.
# Never inspect the full object: Docker metadata may contain secret Env values.
ID = re.compile(r"^[a-f0-9]{12,64}$")
MAX_CONTAINERS = 256


def inspect_reserved_bindings(stdout: str, rows: list[dict]) -> None:
    if len(stdout.encode("utf-8")) > MAX_BYTES:
        raise SharedHostError("Docker reserved port inventory exceeds safe size")
    lines = stdout.splitlines()
    if len(lines) != len(rows):
        raise SharedHostError("Docker reserved port inventory count mismatch")
    for row, raw in zip(rows, lines):
        try:
            bindings = json.loads(raw)
        except ValueError:
            raise SharedHostError("Docker reserved port inventory has invalid JSON") from None
        if bindings is None:
            bindings = {}
        if not isinstance(bindings, dict):
            raise SharedHostError("Docker reserved port inventory has invalid shape")
        project, service = _compose_labels(row["Labels"])
        for target, destinations in bindings.items():
            if not isinstance(target, str) or not isinstance(destinations, (list, type(None))):
                raise SharedHostError("Docker host binding is malformed")
            for destination in destinations or []:
                if (not isinstance(destination, dict)
                    or not isinstance(destination.get("HostIp"), str)
                    or not isinstance(destination.get("HostPort"), str)):
                    raise SharedHostError("Docker host binding destination is malformed")
                host_port = destination["HostPort"]
                if not host_port.isascii() or not host_port.isdecimal():
                    raise SharedHostError("Docker host port is invalid")
                port = int(host_port)
                if port not in PORT_OWNERS:
                    continue
                if (project, service) != PORT_OWNERS[port]:
                    raise SharedHostError(f"Port {port} is reserved by another container")
                if destination["HostIp"] != "127.0.0.1" or target != "8080/tcp":
                    raise SharedHostError(f"Port {port} has unsafe Docker binding")


def verify_shared_a1_containers(runner: Callable = subprocess.run) -> None:
    """Read-only Docker census, including the configured binds of stopped containers."""
    args = ["docker", "ps", "--all", "--format", "{{json .}}"]
    try:
        result = runner(args, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SharedHostError("Docker inventory cannot be inspected") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise SharedHostError("Docker inventory command failed")
    inspect_container_rows(result.stdout)

    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    if len(rows) > MAX_CONTAINERS:
        raise SharedHostError("Too many containers for bounded Docker inventory")
    ids = [row.get("ID") for row in rows]
    if any(not isinstance(cid, str) or not ID.fullmatch(cid) for cid in ids) or len(set(ids)) != len(ids):
        raise SharedHostError("Missing or ambiguous Docker container ID")
    if not ids:
        return
    args = ["docker", "inspect", "--type", "container", "--format",
            "{{json .HostConfig.PortBindings}}", *ids]
    try:
        detail = runner(args, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SharedHostError("Docker reserved port inventory could not run") from exc
    if detail.returncode != 0 or not isinstance(detail.stdout, str):
        raise SharedHostError("Docker reserved port inventory command failed")
    inspect_reserved_bindings(detail.stdout, rows)


if __name__ == "__main__":
    try:
        verify_shared_a1_containers()
    except SharedHostError as exc:
        raise SystemExit("CHRONICLES_SHARED_A1_GUARD_BLOCKED: " + str(exc)) from None
    print("CHRONICLES_SHARED_A1_GUARD_OK")
