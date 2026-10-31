#!/usr/bin/env python3
"""Opt-in OCI check of the installed, inspected rootless CKA lab runtime.

Only the reviewed sudoers command is submitted to the fixed adopted A1.
The agent never receives a shell, Docker credentials or an installer command.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

from oci_control_plane import InventoryError, config_from_env, verified_run_command_host

MARKER = "CKA_LAB_ROOTLESS_RUNTIME "
COMMAND = "set -eu\nsudo -n /usr/local/sbin/shadowops-cka-lab-staging inspect\n"
FIELDS = {"schema", "source_sha", "runtime", "disk_bytes",
          "rootless_and_cgroups_verified", "kubernetes_started", "labs_enabled"}
DISK_BYTES = 8 * 1024**3


def _unique(pairs):
    result = {}
    for name, item in pairs:
        if name in result:
            raise InventoryError("Duplicate runtime field")
        result[name] = item
    return result


def receipt(state, content):
    raw = getattr(content, "text", None)
    code = getattr(content, "exit_code", None)
    if (state != "SUCCEEDED" or type(code) is not int or code != 0
            or type(raw) is not str or not 0 < len(raw) <= 1024):
        raise InventoryError("Runtime inspection did not complete successfully")
    # Exactly one fixed marker and a JSON object; never echo remote text.
    if not raw.strip().startswith(MARKER) or len(raw.strip().splitlines()) != 1:
        raise InventoryError("Missing or ambiguous runtime receipt")
    try:
        result = json.loads(raw.strip()[len(MARKER):], object_pairs_hook=_unique)
    except (ValueError, TypeError):
        raise InventoryError("Malformed runtime receipt") from None
    if (type(result) is not dict or set(result) != FIELDS
            or type(result["schema"]) is not int or result["schema"] != 1
            or type(result["source_sha"]) is not str
            or not re.fullmatch(r"[a-f0-9]{40}", result["source_sha"])
            or result["runtime"] != "dedicated-rootless-user"
            or type(result["disk_bytes"]) is not int or result["disk_bytes"] != DISK_BYTES
            or result["rootless_and_cgroups_verified"] is not True
            or result["kubernetes_started"] is not False
            or result["labs_enabled"] is not False):
        raise InventoryError("Unexpected runtime inspection status")
    # An empty daemon is NOT a deployed Kubernetes lab.
    return {**result, "inspection_only": True}


def execute(sdk, config, *, pause=time.sleep, clock=time.monotonic):
    compartment, instance = verified_run_command_host(sdk, config)
    models = sdk.compute_instance_agent.models
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment,
        execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(
            source=models.InstanceAgentCommandSourceViaTextDetails(text=COMMAND),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT")),
        display_name="cka-lab-rootless-fixed-inspection")
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(
        create_instance_agent_command_details=details).data
    if not getattr(created, "id", None):
        raise InventoryError("Missing runtime inspection reference")
    deadline = clock() + 360
    while clock() < deadline:
        state = client.get_instance_agent_command_execution(
            instance_agent_command_id=created.id, instance_id=instance).data
        status = str(getattr(state, "lifecycle_state", "")).upper()
        if status in {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}:
            return receipt(status, getattr(state, "content", None))
        pause(2)
    raise InventoryError("Runtime inspection timed out")


def main():
    try:
        import oci
        value = execute(oci, config_from_env(oci, os.environ))
    except Exception:
        print("CKA_LAB_RUNTIME_INSPECTION_BLOCKED: no verified installed runtime", file=sys.stderr)
        return 1
    print("CKA_LAB_RUNTIME_VERIFIED " + json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
