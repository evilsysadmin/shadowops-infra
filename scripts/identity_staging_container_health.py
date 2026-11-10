#!/usr/bin/env python3
"""Fixed, read-only OCI probe of Identity staging Docker container health.

No unrestricted sudo, arbitrary commands/paths, logs, env, mounts, secrets or host writes.
Docker output is normalized to a finite whitelist before appearing in CI.
"""
from __future__ import annotations

import os
import re
import sys
import time

from oci_control_plane import InventoryError, config_from_env, verified_run_command_host

# OCI Agent runs as unprivileged ocarun. Docker's socket is root-only. Ask
# sudo for EXACTLY one pre-reviewed root-owned status command, never docker.
SOURCE = "set -eu\nsudo --non-interactive /usr/local/sbin/shadowops-identity-staging status\n"

SERVICES = ("identity-mongo", "identity", "identity-tunnel")
STATES = {"running", "created", "exited", "restarting", "paused", "removing", "dead", "missing"}
HEALTH = {"healthy", "starting", "unhealthy", "none"}
FAILURE_MARKERS = frozenset({
    "IDENTITY_CONTAINERS_DOCKER_UNAVAILABLE",
    "IDENTITY_CONTAINERS_DOCKER_INACCESSIBLE",
    "IDENTITY_CONTAINERS_COLLISION",
    "IDENTITY_CONTAINERS_INVALID_STATE",
})
ENTRY = re.compile(
    r"IDENTITY_CONTAINER service=(identity-mongo|identity|identity-tunnel) "
    r"status=(running|created|exited|restarting|paused|removing|dead|missing) "
    r"health=(healthy|starting|unhealthy|none)\Z"
)
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}
# OCI Run Command control-plane delivery has already exceeded four minutes
# in the protected staging probe. Bound the wait without retrying mutations.
OBSERVATION_DEADLINE_SECONDS = 480
PROBE_FAILURES = frozenset({"command-id", "remote-command", "receipt", "timeout"})


class ProbeBlocked(InventoryError):
    """Fixed, nonsecret OCI failure category; remote output never escapes."""

    def __init__(self, reason):
        if reason not in PROBE_FAILURES:
            raise InventoryError("Invalid fixed OCI failure category")
        self.reason = reason
        super().__init__("OCI Identity probe could not verify container health")


def normalize(output):
    """No raw remote text crosses the logging boundary."""
    lines = output.strip().splitlines()
    if len(lines) == 1 and lines[0] in FAILURE_MARKERS:
        return lines[0]
    if len(lines) != len(SERVICES):
        raise InventoryError("Ambiguous Identity service state")
    rows = {}
    for line in lines:
        found = ENTRY.fullmatch(line)
        if not found or found.group(1) in rows:
            raise InventoryError("Invalid Identity container receipt")
        rows[found.group(1)] = (found.group(2), found.group(3))
    if set(rows) != set(SERVICES):
        raise InventoryError("Missing Identity container receipt")
    return ("IDENTITY_CONTAINER_STATUS " +
            " ".join(service + "=" + rows[service][0] + "/" + rows[service][1]
                     for service in SERVICES))


def observe(sdk, config, *, pause=time.sleep, clock=time.monotonic):
    if SOURCE != "set -eu\nsudo --non-interactive /usr/local/sbin/shadowops-identity-staging status\n":
        raise InventoryError("Unsafe Identity host probe")
    compartment, instance = verified_run_command_host(sdk, config)
    models = sdk.compute_instance_agent.models
    payload = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=SOURCE),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment,
        execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=payload,
        display_name="shadowops-identity-staging-read-only-container-health",
    )
    agent = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    submitted = agent.create_instance_agent_command(
        create_instance_agent_command_details=details,
    ).data
    command_id = getattr(submitted, "id", None)
    if not command_id:
        raise ProbeBlocked("command-id")
    deadline = clock() + OBSERVATION_DEADLINE_SECONDS
    while clock() < deadline:
        result = agent.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance,
        ).data
        state = str(getattr(result, "lifecycle_state", "") or "").upper()
        if state in TERMINAL:
            response = getattr(result, "content", None)
            if state != "SUCCEEDED" or type(getattr(response, "exit_code", None)) is not int or response.exit_code != 0:
                raise ProbeBlocked("remote-command")
            try:
                return normalize(str(getattr(response, "text", "") or ""))
            except InventoryError:
                raise ProbeBlocked("receipt") from None
        pause(2)
    raise ProbeBlocked("timeout")


def main():
    if sys.argv[1:] == ["self-test"]:
        fixture = "\n".join(
            "IDENTITY_CONTAINER service=" + service + " status=running health=healthy"
            for service in SERVICES
        )
        if not normalize(fixture).startswith("IDENTITY_CONTAINER_STATUS "):
            raise SystemExit(1)
        print("IDENTITY_CONTAINER_PROBE_SELF_TEST_OK")
        return 0
    try:
        if sys.argv[1:] != ["run"]:
            raise InventoryError("Unknown fixed Identity container probe")
        import oci
        print(observe(oci, config_from_env(oci, os.environ)))
        return 0
    except Exception as exc:
        # Only the finite reason is exported; never surface OCI/host exceptions.
        reason = " reason=" + exc.reason if isinstance(exc, ProbeBlocked) else ""
        kind = "InventoryError" if isinstance(exc, ProbeBlocked) else type(exc).__name__
        print("IDENTITY_CONTAINER_PROBE_BLOCKED type=" + kind + reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
