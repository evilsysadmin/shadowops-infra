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
    managed_count = 0
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
            if service != "chronicles-api":
                raise SharedHostError("Unexpected service inside Chronicles staging project")
            managed_count += 1
            if managed_count > 1:
                raise SharedHostError("Ambiguous duplicate Chronicles staging containers")
        if project == PROJECT_WEB and service != "chronicles-web":
            raise SharedHostError("Unexpected service inside Chronicles staging web project")
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


def verify_shared_a1_containers(runner: Callable = subprocess.run) -> None:
    """Read-only Docker census; fail closed if Docker cannot be inspected."""
    args = ["docker", "ps", "--all", "--format", "{{json .}}"]
    try:
        result = runner(args, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SharedHostError("Docker inventory cannot be inspected") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise SharedHostError("Docker inventory command failed")
    inspect_container_rows(result.stdout)


if __name__ == "__main__":
    try:
        verify_shared_a1_containers()
    except SharedHostError as exc:
        raise SystemExit("CHRONICLES_SHARED_A1_GUARD_BLOCKED: " + str(exc)) from None
    print("CHRONICLES_SHARED_A1_GUARD_OK")
