#!/usr/bin/env python3
"""Read-only OCI inventory of the latest fixed Atlas Identity release command.

No command is created. No host SSH/root/Docker/Atlas operation is permitted.
Only a bounded nonsecret summary is emitted, even on OCI SDK errors.
"""
from __future__ import annotations
import os
import re
import sys
from datetime import datetime, timezone

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



# The original failed job entered OCI release at 2026-11-10T12:56:00Z.
# Bound the *creation* inventory to that UTC window, not merely the last 25
# executions; an absent execution alone does not prove no command was created.
ATTEMPT = datetime(2026, 11, 10, 12, 56, tzinfo=timezone.utc)


def inspect_created(sdk, config, *, max_pages=5):
    compartment, _ = resolve_existing_host(sdk, config)
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    page = None
    for _ in range(max_pages):
        options = {"compartment_id": compartment, "limit": 100,
                   "sort_by": "TIMECREATED", "sort_order": "DESC"}
        if page:
            options["page"] = page
        response = client.list_instance_agent_commands(**options)
        rows = list(response.data)
        for row in rows:
            created = getattr(row, "time_created", None)
            if not isinstance(created, datetime) or created.tzinfo is None:
                return "IDENTITY_ATLAS_COMMAND_AUDIT created=window-unverifiable"
            if created >= ATTEMPT and getattr(row, "display_name", None) == NAME:
                return "IDENTITY_ATLAS_COMMAND_AUDIT created=observed-since-attempt"
        headers = getattr(response, "headers", None) or {}
        next_page = headers.get("opc-next-page")
        # Descending time order: if the oldest row is already before the
        # attempt, the entire relevant time window has been covered.
        if (not rows or rows[-1].time_created <= ATTEMPT or not next_page):
            return "IDENTITY_ATLAS_COMMAND_AUDIT created=not-observed-since-attempt"
        if not isinstance(next_page, str) or len(next_page) > 256:
            return "IDENTITY_ATLAS_COMMAND_AUDIT created=window-unverifiable"
        page = next_page
    return "IDENTITY_ATLAS_COMMAND_AUDIT created=window-incomplete"


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
        phase = "creation-inventory"
        print(inspect_created(oci, config))
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
