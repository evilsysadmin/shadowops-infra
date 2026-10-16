#!/usr/bin/env python3
"""One-shot nonprivileged diagnostics for Chronicles web deployment authority.

Only fixed, read-only checks on the already adopted OCI A1. The GitHub workflow
is temporarily allowed to run this check on trusted main exactly once, then
must be returned to manual-only operation.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Any

from oci_control_plane import InventoryError, config_from_env, inspect, resolve_existing_host

PREFIX = "SHADOWOPS_CHRONICLES_BOOT_ACCESS"
COMMAND = """set -eu
test "$(uname -m)" = 'aarch64'
curl -fsS --max-time 8 http://127.0.0.1:4000/api/ready >/dev/null
if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then docker=yes; else docker=no; fi
if test -d /opt/shadowops-infra/.git; then repo=yes; else repo=no; fi
if test -x /usr/local/sbin/shadowops-chronicles-web-deploy; then wrapper=yes; else wrapper=no; fi
if command -v gh >/dev/null 2>&1; then gh=yes; else gh=no; fi
printf 'SHADOWOPS_CHRONICLES_BOOT_ACCESS docker=%s repo=%s wrapper=%s gh=%s\\n' "$docker" "$repo" "$wrapper" "$gh"
"""
EXPECTED = re.compile(
    r"^SHADOWOPS_CHRONICLES_BOOT_ACCESS docker=(yes|no) repo=(yes|no) wrapper=(yes|no) gh=(yes|no)$"
)
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def fixed_command(value: str) -> None:
    if value != COMMAND or len(value.encode()) > 4096:
        raise InventoryError("Only the reviewed Chronicles capability command is permitted")
    for forbidden in ("sudo ", "docker run", "docker compose up", "docker pull",
                      "docker inspect", "docker ps", "docker exec", "ssh ", "terraform",
                      "git fetch", "PRIVATE_KEY", "JWT_SECRET", "printenv", "env |"):
        if forbidden in value:
            raise InventoryError("Capability probe contains a forbidden operation")


def run(sdk: Any, config: dict[str, str], *, pause=time.sleep, clock=time.monotonic) -> str:
    inspect(sdk, config)
    compartment_id, instance_id = resolve_existing_host(sdk, config)
    fixed_command(COMMAND)
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
        display_name="shadowops-chronicles-first-boot-capabilities",
    )
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(create_instance_agent_command_details=details).data
    command_id = str(getattr(created, "id", "") or "")
    if not command_id:
        raise InventoryError("No OCI capability probe command ID")
    deadline = clock() + 420
    while clock() < deadline:
        execution = client.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance_id,
        ).data
        status = str(getattr(execution, "lifecycle_state", "") or "").upper()
        if status in TERMINAL:
            content = getattr(execution, "content", None)
            output = str(getattr(content, "text", "") or "").strip()
            if (status != "SUCCEEDED" or getattr(content, "exit_code", None) not in (0, None)
                    or not EXPECTED.fullmatch(output)):
                raise InventoryError("Untrusted or unsuccessful Chronicles capability observation")
            # Only an exact four-boolean marker, never arbitrary remote stdout.
            print(output)
            return output
        pause(2)
    raise InventoryError("OCI capability probe timed out")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "self-test"))
    args = parser.parse_args()
    if args.operation == "self-test":
        fixed_command(COMMAND)
        if not EXPECTED.fullmatch(PREFIX + " docker=no repo=no wrapper=no gh=no"):
            raise AssertionError("Expected marker format invalid")
        print("SHADOWOPS_CHRONICLES_BOOT_CAPABILITY_TEST_OK")
        return 0
    try:
        import oci
        run(oci, config_from_env(oci, os.environ))
    except Exception as exc:
        print("SHADOWOPS_CHRONICLES_BOOT_CAPABILITY_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
