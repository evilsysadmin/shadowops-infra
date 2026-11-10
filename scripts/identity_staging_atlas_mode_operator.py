#!/usr/bin/env python3
"""Root-only, read-only operator proof of the Atlas takeover marker and actual Identity mount.

Runs solely over the existing human Cloudflare Access SSH path, not the OCI agent
or a new sudoers grant. Never reads config contents, credentials, Docker Env,
container logs or marker contents; only fixed metadata is inspected.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

PROJECT = "shadowops-identity-staging"
MARKER = Path("/var/lib/shadowops/identity-staging/atlas-active")
CONFIG_DESTINATION = "/run/secrets/identity-staging.json"
LOCAL_CONFIG = "/etc/shadowops/identity-staging/service.json"
ATLAS_CONFIG = "/etc/shadowops/identity-staging/atlas-service.json"
STATES = frozenset({"running", "exited", "created", "restarting", "paused", "dead"})
ERROR = "IDENTITY_ATLAS_MODE_BLOCKED"
IDENTITY = re.compile(r"[a-f0-9]{12,64}\Z")


class ModeError(ValueError):
    def __init__(self, reason: str):
        if reason not in {"docker", "identity-ambiguous", "mount-ambiguous",
                          "network-ambiguous", "state-ambiguous", "marker-unsafe"}:
            raise ValueError("Unknown fixed mode reason")
        self.reason = reason
        super().__init__("Identity Atlas mode could not be verified")


def inspect_mode(*, marker=MARKER, runner=subprocess.run, uid=os.geteuid):
    """Return a single finite, nonsecret status or raise a fixed ModeError."""
    if uid() != 0:
        return ERROR + " reason=not-root"
    try:
        try:
            meta = marker.lstat()
        except FileNotFoundError:
            marked = "absent"
        else:
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                    meta.st_mode & 0o022):
                raise ModeError("marker-unsafe")
            marked = "present"

        def docker(*args):
            result = runner(["docker", *args], capture_output=True, text=True,
                            timeout=8, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
            if (result.returncode != 0 or not isinstance(result.stdout, str) or
                    len(result.stdout) > 32768):
                raise ModeError("docker")
            return result.stdout.strip()

        ids = docker("ps", "-aq",
                     "--filter", "label=com.docker.compose.project=" + PROJECT,
                     "--filter", "label=com.docker.compose.service=identity").splitlines()
        if len(ids) != 1 or not IDENTITY.fullmatch(ids[0]):
            raise ModeError("identity-ambiguous")
        container_id = ids[0]
        mounts = json.loads(docker("inspect", "--type", "container",
                                   "--format", "{{json .Mounts}}", container_id))
        if not isinstance(mounts, list) or len(mounts) > 16:
            raise ModeError("mount-ambiguous")
        config_mounts = [m for m in mounts if isinstance(m, dict) and
                         m.get("Destination") == CONFIG_DESTINATION]
        if len(config_mounts) != 1 or config_mounts[0].get("Type") != "bind" or config_mounts[0].get("RW") is not False:
            raise ModeError("mount-ambiguous")
        source = config_mounts[0].get("Source")
        networks = json.loads(docker("inspect", "--type", "container",
                                     "--format", "{{json .NetworkSettings.Networks}}",
                                     container_id))
        if not isinstance(networks, dict):
            raise ModeError("network-ambiguous")
        network_names = set(networks)
        origin = PROJECT + "-origin"
        if source == LOCAL_CONFIG and network_names == {origin, PROJECT + "-database"}:
            config = "local"
        elif source == ATLAS_CONFIG and network_names == {origin, PROJECT + "-atlas-egress"}:
            config = "atlas"
        else:
            raise ModeError("network-ambiguous")
        state = docker("inspect", "--type", "container", "--format",
                       "{{.State.Status}}", container_id)
        if state not in STATES:
            raise ModeError("state-ambiguous")
        return "IDENTITY_ATLAS_MODE marker=" + marked + " config=" + config + " container=" + state
    except ModeError:
        raise
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        raise ModeError("docker") from None


def main():
    if sys.argv[1:] or os.geteuid() != 0:
        print(ERROR + " reason=not-root-or-arguments")
        return 1
    try:
        print(inspect_mode())
        return 0
    except ModeError as exc:
        print(ERROR + " reason=" + exc.reason)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
