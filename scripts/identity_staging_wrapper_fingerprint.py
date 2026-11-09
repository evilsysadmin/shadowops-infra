#!/usr/bin/env python3
"""Nonprivileged OCI fingerprint of installed Identity staging code only.

Does not read Vault/Compose/private files or expose host output to CI.
This creates a read-only OCI agent command receipt on the pinned A1.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys
import time

from oci_control_plane import InventoryError, config_from_env, verified_run_command_host

SOURCES = (
    ("host/identity-staging-deploy.py", "/usr/local/sbin/shadowops-identity-staging", "755"),
    ("scripts/identity_staging_bundle.py", "/usr/local/lib/shadowops/identity_staging_bundle.py", "644"),
)
OBSERVATION = """set -eu
wrapper=/usr/local/sbin/shadowops-identity-staging
bundle=/usr/local/lib/shadowops/identity_staging_bundle.py
for file in "$wrapper" "$bundle"; do
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    printf '%s\n' IDENTITY_WRAPPER_FINGERPRINT_MISSING
    exit 0
  fi
  if [ ! -f "$file" ] || [ -L "$file" ] || [ "$(stat -c %u -- "$file")" != 0 ]; then
    printf '%s\n' IDENTITY_WRAPPER_FINGERPRINT_UNSAFE
    exit 0
  fi
done
if [ "$(stat -c %a -- "$wrapper")" != 755 ] ||
   [ "$(stat -c %a -- "$bundle")" != 644 ]; then
  printf '%s\n' IDENTITY_WRAPPER_FINGERPRINT_UNSAFE
  exit 0
fi
hash1="$(sha256sum -- "$wrapper")"
hash2="$(sha256sum -- "$bundle")"
printf 'IDENTITY_WRAPPER_FINGERPRINT_SHA256 %s %s\n' "${hash1%% *}" "${hash2%% *}"
"""
FINGERPRINT = re.compile(r"IDENTITY_WRAPPER_FINGERPRINT_SHA256 ([0-9a-f]{64}) ([0-9a-f]{64})\Z")
VERDICTS = {"IDENTITY_WRAPPER_FINGERPRINT_MISSING", "IDENTITY_WRAPPER_FINGERPRINT_UNSAFE"}
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def trusted_digests(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    results = []
    for source, _, _ in SOURCES:
        path = root / source
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise InventoryError("Untrusted installed-wrapper comparison source")
        results.append(hashlib.sha256(path.read_bytes()).hexdigest())
    return tuple(results)


def verdict(output, expected):
    if not isinstance(expected, tuple) or len(expected) != 2 or any(
        not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{64}", v) is None for v in expected
    ):
        raise InventoryError("Invalid source digests")
    lines = output.strip().splitlines()
    if len(lines) != 1:
        raise InventoryError("Unexpected private host diagnostic output")
    if lines[0] in VERDICTS:
        return lines[0]
    found = FINGERPRINT.fullmatch(lines[0])
    if not found:
        raise InventoryError("Unexpected private host diagnostic output")
    same_wrapper = found.group(1) == expected[0]
    same_bundle = found.group(2) == expected[1]
    if same_wrapper and same_bundle:
        return "IDENTITY_WRAPPER_FINGERPRINT_CURRENT"
    if not same_wrapper and not same_bundle:
        return "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_BOTH"
    if not same_wrapper:
        return "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_WRAPPER"
    return "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_BUNDLE"


def diagnose(sdk, config, expected, *, pause=time.sleep, clock=time.monotonic):
    if "sudo " in OBSERVATION or "docker " in OBSERVATION or "ssh " in OBSERVATION or len(OBSERVATION) > 3000:
        raise InventoryError("Unsafe fixed host fingerprint request")
    compartment, instance = verified_run_command_host(sdk, config)
    models = sdk.compute_instance_agent.models
    content = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=OBSERVATION),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment,
        execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=content,
        display_name="shadowops-identity-read-only-wrapper-fingerprint",
    )
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    command = client.create_instance_agent_command(create_instance_agent_command_details=details).data
    command_id = getattr(command, "id", None)
    if not command_id:
        raise InventoryError("Host fingerprint command receipt missing")
    deadline = clock() + 240
    while clock() < deadline:
        result = client.get_instance_agent_command_execution(
            instance_agent_command_id=command_id,
            instance_id=instance,
        ).data
        state = str(getattr(result, "lifecycle_state", "") or "").upper()
        if state in TERMINAL:
            response = getattr(result, "content", None)
            if state != "SUCCEEDED" or type(getattr(response, "exit_code", None)) is not int or response.exit_code != 0:
                raise InventoryError("Host fingerprint execution unsuccessful")
            return verdict(str(getattr(response, "text", "") or ""), expected)
        pause(2)
    raise InventoryError("Host fingerprint execution timed out")


def main():
    try:
        if sys.argv[1:] == ["self-test"]:
            expected = ("a" * 64, "b" * 64)
            if verdict("IDENTITY_WRAPPER_FINGERPRINT_SHA256 " + "a" * 64 + " " + "b" * 64, expected) != "IDENTITY_WRAPPER_FINGERPRINT_CURRENT":
                raise InventoryError("Host fingerprint self-test failed")
            print("IDENTITY_WRAPPER_FINGERPRINT_SELF_TEST_OK")
            return 0
        if sys.argv[1:] != ["run"]:
            raise InventoryError("Usage: self-test or run")
        import oci
        result = diagnose(oci, config_from_env(oci, os.environ), trusted_digests())
        # A finite status only: never print remote command stdout/digests.
        print(result)
        return 0
    except Exception as exc:
        print("IDENTITY_WRAPPER_FINGERPRINT_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
