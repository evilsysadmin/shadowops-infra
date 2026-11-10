#!/usr/bin/env python3
"""Read-only OCI inventory of the latest fixed Atlas Identity release command.

No command is created. No host SSH/root/Docker/Atlas operation is permitted.
Only a bounded nonsecret summary is emitted, even on OCI SDK errors.
"""
from __future__ import annotations
import os
import re
import sys

from oci_control_plane import config_from_env, resolve_existing_host

NAME = "identity-staging-atlas-release"
SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
DIGEST = "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91"
SUCCEEDED = "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + SHA + " digest=" + DIGEST
BLOCKED = re.compile(r"IDENTITY_ATLAS_DEPLOY_BLOCKED type=[A-Za-z]{1,40}\Z")
STATES = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED", "ACCEPTED", "IN_PROGRESS"})


def interpret(execution):
    state = str(getattr(execution, "lifecycle_state", "")).upper()
    if state not in STATES:
        state = "UNKNOWN"
    content = getattr(execution, "content", None)
    code = getattr(content, "exit_code", None)
    exit_status = str(code) if type(code) is int and -255 <= code <= 255 else "missing"
    output = str(getattr(content, "text", "") or "").strip()
    receipt = "accepted" if (state == "SUCCEEDED" and exit_status == "0"
                             and output == SUCCEEDED) else (
        "blocked" if BLOCKED.fullmatch(output) else "absent-or-unrecognized")
    return f"IDENTITY_ATLAS_RELEASE_AUDIT command=observed state={state} exit={exit_status} receipt={receipt}"


def inspect(sdk, config):
    compartment, instance = resolve_existing_host(sdk, config)
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    response = client.list_instance_agent_command_executions(
        compartment_id=compartment, instance_id=instance, limit=25,
        sort_by="TIMECREATED", sort_order="DESC")
    rows = list(response.data)
    matching = [row for row in rows if getattr(row, "display_name", None) == NAME
                and getattr(row, "instance_id", None) == instance]
    if not matching:
        return "IDENTITY_ATLAS_RELEASE_AUDIT command=not-observed-in-recent-25"
    command_id = getattr(matching[0], "instance_agent_command_id", None)
    if not isinstance(command_id, str) or not command_id:
        return "IDENTITY_ATLAS_RELEASE_AUDIT command=unverifiable"
    execution = client.get_instance_agent_command_execution(
        instance_agent_command_id=command_id, instance_id=instance).data
    return interpret(execution)


def main():
    if sys.argv[1:]:
        print("IDENTITY_ATLAS_RELEASE_AUDIT_BLOCKED phase=arguments", file=sys.stderr)
        return 1
    phase = "credentials"
    try:
        import oci
        config = config_from_env(oci, os.environ)
        phase = "inventory"
        print(inspect(oci, config))
        return 0
    except Exception as exc:
        # Only the bounded phase and SDK class name; never OCI URLs, request IDs,
        # host output, credentials or exception messages.
        kind = type(exc).__name__
        if not re.fullmatch(r"[A-Za-z]{1,48}", kind):
            kind = "Unknown"
        print(f"IDENTITY_ATLAS_RELEASE_AUDIT_BLOCKED phase={phase} type={kind}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
