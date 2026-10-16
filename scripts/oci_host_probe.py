#!/usr/bin/env python3
"""Run a fixed, non-privileged HOST observation through OCI Run Command.

Unlike inventory, sending a Run Command creates an OCI command record and
executes a script on the host; the script is deliberately read-only and has
no sudo, deployment, SSH, credentials or arbitrary user inputs.
"""
from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from oci_control_plane import InventoryError, config_from_env, inspect, resolve_existing_host

HOST_READY = "SHADOWOPS_EXISTING_A1_HOST_PROBE_OK"
HOST_COMMAND = """set -eu
test "$(uname -m)" = 'aarch64'
test -d /opt/chess-studio/repo
test -x /usr/local/sbin/chess-studio-deploy
command -v docker >/dev/null 2>&1
docker compose version >/dev/null 2>&1
systemctl is-active --quiet docker
curl --fail --silent --show-error --max-time 8 http://127.0.0.1:4000/api/ready >/dev/null
printf '%s\\n' 'SHADOWOPS_EXISTING_A1_HOST_PROBE_OK'
"""

TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def assert_command_safe(command: str) -> None:
    if command != HOST_COMMAND or len(command.encode()) > 4096:
        raise InventoryError("Only the fixed host observation command is permitted")
    for forbidden in ("sudo ", "docker run", "docker compose up", "docker compose down",
                      "docker rm", "systemctl restart", "terraform", "ssh ", "git fetch",
                      "curl -X", "https://api.", "PRIVATE_KEY", "JWT_SECRET"):
        if forbidden in command:
            raise InventoryError("Host probe contains a forbidden operation")


def execute(sdk: Any, config: dict[str, str], *, pause=time.sleep, clock=time.monotonic) -> None:
    # Check remote instance identity and plugin health *before* issuing a command.
    inspect(sdk, config)
    compartment_id, instance_id = resolve_existing_host(sdk, config)
    assert_command_safe(HOST_COMMAND)
    models = sdk.compute_instance_agent.models
    command = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=HOST_COMMAND),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment_id,
        execution_time_out_in_seconds=120,
        target=models.InstanceAgentCommandTarget(instance_id=instance_id),
        content=command,
        display_name="shadowops-existing-a1-read-only-probe",
    )
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(create_instance_agent_command_details=details).data
    command_id = str(getattr(created, "id", "") or "")
    if not command_id:
        raise InventoryError("OCI host probe returned no command ID")
    deadline = clock() + 450
    while clock() < deadline:
        execution = client.get_instance_agent_command_execution(
            instance_agent_command_id=command_id,
            instance_id=instance_id,
        ).data
        state = str(getattr(execution, "lifecycle_state", "UNKNOWN") or "UNKNOWN")
        if state in TERMINAL:
            content = getattr(execution, "content", None)
            code = getattr(content, "exit_code", None)
            output = str(getattr(content, "text", "") or "")
            if state != "SUCCEEDED" or code not in (0, None):
                raise InventoryError("OCI host probe execution failed")
            if HOST_READY not in {line.strip() for line in output.splitlines()}:
                raise InventoryError("OCI host probe success marker missing")
            # Never echo remote stdout to runner logs.
            print(HOST_READY)
            return
        pause(2)
    raise InventoryError("OCI host probe timed out")


def self_test() -> None:
    assert_command_safe(HOST_COMMAND)
    try:
        assert_command_safe("sudo docker ps")
    except InventoryError:
        pass
    else:
        raise AssertionError("Arbitrary command accepted")
    print("SHADOWOPS_OCI_HOST_PROBE_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("run", "self-test"))
    args = parser.parse_args()
    if args.operation == "self-test":
        self_test()
        return 0
    try:
        import oci
        import os
        execute(oci, config_from_env(oci, os.environ))
    except (InventoryError, Exception) as exc:
        # Fail closed without logging SDK exception details or remote output.
        print("SHADOWOPS_OCI_HOST_PROBE_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
