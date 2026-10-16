#!/usr/bin/env python3
"""Fixed read-only OCI A1 check for Chronicles' *future* staging host ports.

OCI Instance Agent executes a constant command as its unprivileged account.
This is a preliminary listener check, NOT a Docker ownership audit or deploy.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

from oci_control_plane import InventoryError, config_from_env, inspect, resolve_existing_host

READY = "SHADOWOPS_CHRONICLES_A1_PORTS_AVAILABLE"
COMMAND = """set -eu
test "$(uname -m)" = 'aarch64'
test -d /opt/chess-studio/repo
command -v ss >/dev/null 2>&1
command -v docker >/dev/null 2>&1
docker compose version >/dev/null 2>&1
curl --fail --silent --show-error --max-time 8 http://127.0.0.1:4000/api/ready >/dev/null
listeners="$(ss -H -ltn '( sport = :18081 or sport = :18082 )')"
test -z "$listeners"
printf '%s\\n' 'SHADOWOPS_CHRONICLES_A1_PORTS_AVAILABLE'
"""
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def assert_fixed_command(command: str) -> None:
    if command != COMMAND or len(command.encode("utf-8")) > 4096:
        raise InventoryError("Only the fixed Chronicles listener preflight is permitted")
    for forbidden in (
        "sudo ", "docker run", "docker compose up", "docker compose down",
        "docker rm", "systemctl restart", "terraform", "ssh ", "git fetch",
        "PRIVATE_KEY", "JWT_SECRET", "curl -X", "curl --data",
    ):
        if forbidden in command:
            raise InventoryError("Chronicles host preflight contains forbidden operation")


def execute(sdk: Any, config: dict[str, str], *, pause=time.sleep,
            clock=time.monotonic) -> None:
    # Reject a different instance, absent agent, or ambiguous host before sending a command.
    inspect(sdk, config)
    compartment_id, instance_id = resolve_existing_host(sdk, config)
    assert_fixed_command(COMMAND)
    models = sdk.compute_instance_agent.models
    content = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=COMMAND),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment_id,
        execution_time_out_in_seconds=120,
        target=models.InstanceAgentCommandTarget(instance_id=instance_id),
        content=content,
        display_name="shadowops-chronicles-a1-ports-readonly",
    )
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(
        create_instance_agent_command_details=details
    ).data
    command_id = str(getattr(created, "id", "") or "")
    if not command_id:
        raise InventoryError("OCI Chronicles preflight returned no command ID")
    deadline = clock() + 450
    while clock() < deadline:
        execution = client.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance_id
        ).data
        state = str(getattr(execution, "lifecycle_state", "UNKNOWN") or "UNKNOWN")
        if state in TERMINAL:
            content = getattr(execution, "content", None)
            exit_code = getattr(content, "exit_code", None)
            output = str(getattr(content, "text", "") or "")
            if state != "SUCCEEDED" or exit_code not in (0, None) or output.strip() != READY:
                raise InventoryError("Chronicles port preflight rejected remote host state")
            # Deliberately discard all OCI remote output except this fixed marker.
            print(READY)
            return
        pause(2)
    raise InventoryError("OCI Chronicles port preflight timed out")


def self_test() -> None:
    assert_fixed_command(COMMAND)
    try:
        assert_fixed_command("sudo docker ps")
    except InventoryError:
        pass
    else:
        raise AssertionError("Arbitrary remote host command was accepted")
    print("SHADOWOPS_CHRONICLES_A1_PORTS_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "self-test"))
    arguments = parser.parse_args()
    if arguments.operation == "self-test":
        self_test()
        return 0
    try:
        import oci
        execute(oci, config_from_env(oci, os.environ))
    except Exception as exc:
        # OCI errors and host stdout may contain private identifiers.
        print("SHADOWOPS_CHRONICLES_A1_PORTS_BLOCKED type=" +
              type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
