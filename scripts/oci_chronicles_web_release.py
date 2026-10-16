#!/usr/bin/env python3
"""Send only an admitted Chronicles web digest to its fixed root-owned wrapper.

No arbitrary OCI shell, Docker command, SSH key, Oracle secret or environment
variable is ever sent over Run Command. The host wrapper must be installed by
an authorized operator before this script is dispatchable.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Any

from oci_control_plane import InventoryError, config_from_env, inspect, resolve_existing_host

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WRAPPER = "/usr/local/sbin/shadowops-chronicles-web"
MARKER = "CHRONICLES_WEB_OCI_STAGING_SMOKE_OK digest="
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def command_for(digest: str) -> str:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise InventoryError("Invalid immutable Chronicles web digest")
    command = (
        "set -euo pipefail\n"
        "test -x /usr/local/sbin/shadowops-chronicles-web\n"
        "sudo --non-interactive /usr/local/sbin/shadowops-chronicles-web deploy " + digest + "\n"
    )
    if len(command.encode()) > 4096 or WRAPPER not in command:
        raise InventoryError("Chronicles web Run Command exceeds fixed policy")
    return command


def execute(
    sdk: Any, config: dict[str, str], digest: str, *,
    pause=time.sleep, clock=time.monotonic
) -> str:
    fixed = command_for(digest)
    inspect(sdk, config)
    compartment_id, instance_id = resolve_existing_host(sdk, config)
    models = sdk.compute_instance_agent.models
    content = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=fixed),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment_id,
        execution_time_out_in_seconds=420,
        target=models.InstanceAgentCommandTarget(instance_id=instance_id),
        content=content,
        display_name="shadowops-chronicles-web-signed-staging-release",
    )
    agent = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = agent.create_instance_agent_command(
        create_instance_agent_command_details=details,
    ).data
    command_id = str(getattr(created, "id", "") or "")
    if not command_id:
        raise InventoryError("Chronicles deploy did not return an OCI command ID")
    deadline = clock() + 650
    while clock() < deadline:
        execution = agent.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance_id,
        ).data
        status = str(getattr(execution, "lifecycle_state", "") or "").upper()
        if status in TERMINAL:
            result = getattr(execution, "content", None)
            stdout = str(getattr(result, "text", "") or "").strip()
            if (status != "SUCCEEDED" or getattr(result, "exit_code", None) != 0
                    or stdout != MARKER + digest):
                # Never echo Oracle's raw remote output.
                raise InventoryError("Chronicles web root-wrapper smoke did not succeed")
            print(MARKER + digest)
            return stdout
        pause(3)
    raise InventoryError("Chronicles web OCI release timed out")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=False, default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        sample = "sha256:" + "a" * 64
        command = command_for(sample)
        assert command.count("sudo --non-interactive ") == 1
        assert "docker " not in command and "chess-studio-deploy" not in command
        print("SHADOWOPS_CHRONICLES_WEB_OCI_RELEASE_SELF_TEST_OK")
        return 0
    try:
        import oci
        execute(oci, config_from_env(oci, os.environ), args.digest)
    except Exception as exc:
        print("CHRONICLES_WEB_OCI_RELEASE_BLOCKED type=" +
              type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
