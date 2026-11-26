#!/usr/bin/env python3
"""Read-only, nonsecret classification of the live Identity container wiring."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

PROJECT = "shadowops-identity-staging"
TARGET = "/run/secrets/identity-staging.json"
ROOT = "/etc/shadowops/identity-staging/"
CONTAINER_ID = re.compile(r"[a-f0-9]{12,64}\Z")
STATES = frozenset({"running", "exited", "created", "restarting", "paused", "dead"})


def docker(args):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=10,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > 32768:
        raise ValueError("docker-read")
    return result.stdout.strip()


def classify():
    if os.geteuid() != 0:
        return "IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=authority"
    ids = docker([
        "ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT,
        "--filter", "label=com.docker.compose.service=identity",
    ]).splitlines()
    if not ids:
        return "IDENTITY_ATLAS_CONTAINER_DETAIL count=missing mount=missing networks=missing state=missing"
    if len(ids) != 1 or not CONTAINER_ID.fullmatch(ids[0]):
        return "IDENTITY_ATLAS_CONTAINER_DETAIL count=ambiguous mount=ambiguous networks=ambiguous state=ambiguous"

    container_id = ids[0]
    mounts = json.loads(docker([
        "inspect", "--type", "container", "--format", "{{json .Mounts}}", container_id,
    ]))
    networks = json.loads(docker([
        "inspect", "--type", "container", "--format", "{{json .NetworkSettings.Networks}}", container_id,
    ]))
    state = docker([
        "inspect", "--type", "container", "--format", "{{.State.Status}}", container_id,
    ])

    selected = [m for m in mounts if isinstance(m, dict) and m.get("Destination") == TARGET] if isinstance(mounts, list) else []
    if len(selected) != 1:
        mount_kind = "missing" if not selected else "ambiguous"
    else:
        mount = selected[0]
        source_map = {
            ROOT + "service.json": "local",
            ROOT + "atlas-service.json": "atlas",
            ROOT + "atlas-snooker-service.json": "snooker",
            ROOT + "atlas-staradvs-service.json": "staradvs",
        }
        mount_kind = source_map.get(mount.get("Source"), "other")
        if mount.get("Type") != "bind" or mount.get("RW") is not False:
            mount_kind = "unsafe"

    if not isinstance(networks, dict):
        network_kind = "ambiguous"
    else:
        names = set(networks)
        if names == {PROJECT + "-origin", PROJECT + "-atlas-egress"}:
            network_kind = "atlas"
        elif names == {PROJECT + "-origin", PROJECT + "-database"}:
            network_kind = "local"
        else:
            network_kind = "other"

    state_kind = state if state in STATES else "unknown"
    return ("IDENTITY_ATLAS_CONTAINER_DETAIL count=single"
            + " mount=" + mount_kind
            + " networks=" + network_kind
            + " state=" + state_kind)


def main():
    if sys.argv[1:]:
        print("IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=arguments")
        return 1
    try:
        print(classify())
        return 0
    except Exception:
        print("IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=read-only-probe")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
