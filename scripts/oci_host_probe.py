#!/usr/bin/env python3
"""Run a fixed, non-privileged HOST observation through OCI Run Command.

Unlike inventory, sending a Run Command creates an OCI command record and
executes a script on the host; the script is deliberately read-only and has
no sudo, deployment, SSH, credentials or arbitrary user inputs.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys
import time
from typing import Any

from oci_control_plane import InventoryError, config_from_env, verified_run_command_host

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

# A second *fixed*, non-privileged host read: one installed root-owned file.
# Never send a caller-controlled path, command, or trusted expected SHA to A1.
WRAPPER_COMMAND = """set -eu
helper=/usr/local/sbin/shadowops-chronicles-api
if [ ! -e "$helper" ] && [ ! -L "$helper" ]; then
  printf '%s\n' 'CHRONICLES_API_WRAPPER_MISSING'
  exit 0
fi
if [ ! -f "$helper" ] || [ -L "$helper" ] || [ ! -x "$helper" ] ||
   [ "$(stat -c %u -- "$helper")" != 0 ]; then
  printf '%s\n' 'CHRONICLES_API_WRAPPER_UNSAFE'
  exit 0
fi
mode="$(stat -c %a -- "$helper")"
case "$mode" in
  [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
  *) printf '%s\n' 'CHRONICLES_API_WRAPPER_UNSAFE'; exit 0 ;;
esac
if [ "$((0$mode & 022))" -ne 0 ]; then
  printf '%s\n' 'CHRONICLES_API_WRAPPER_UNSAFE'
  exit 0
fi
hash="$(sha256sum -- "$helper")"
printf 'CHRONICLES_API_WRAPPER_SHA256 %s\n' "${hash%% *}"
"""
WRAPPER_HASH = re.compile(r"CHRONICLES_API_WRAPPER_SHA256 ([0-9a-f]{64})")
WRAPPER_ABSENT = {"CHRONICLES_API_WRAPPER_MISSING", "CHRONICLES_API_WRAPPER_UNSAFE"}


def local_wrapper_digest() -> str:
    """Hash trusted checkout bytes, not a remote-supplied path."""
    source = Path(__file__).resolve().parents[1] / "host/chronicles-api-deploy.py"
    if not source.is_file() or source.is_symlink():
        raise InventoryError("Trusted Chronicles wrapper source missing or unsafe")
    return hashlib.sha256(source.read_bytes()).hexdigest()


def wrapper_verdict(output: str, expected_digest: str) -> str:
    """Convert an exact one-line host observation to a safe finite verdict."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise InventoryError("Invalid expected wrapper digest")
    lines = output.splitlines()
    if len(lines) != 1:
        raise InventoryError("Untrusted wrapper observation")
    if lines[0] in WRAPPER_ABSENT:
        return lines[0]
    match = WRAPPER_HASH.fullmatch(lines[0])
    if match is None:
        raise InventoryError("Untrusted wrapper observation")
    return ("CHRONICLES_API_WRAPPER_CURRENT" if match.group(1) == expected_digest
            else "CHRONICLES_API_WRAPPER_OUTDATED")


TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def assert_command_safe(command: str) -> None:
    if command not in (HOST_COMMAND, WRAPPER_COMMAND) or len(command.encode()) > 4096:
        raise InventoryError("Only the fixed host observation command is permitted")
    for forbidden in ("sudo ", "docker run", "docker compose up", "docker compose down",
                      "docker rm", "systemctl restart", "terraform", "ssh ", "git fetch",
                      "curl -X", "https://api.", "PRIVATE_KEY", "JWT_SECRET"):
        if forbidden in command:
            raise InventoryError("Host probe contains a forbidden operation")


def execute(sdk: Any, config: dict[str, str], *, pause=time.sleep,
            clock=time.monotonic, probe: str = "host", expected_digest: str = "") -> None:
    if probe not in ("host", "wrapper"):
        raise InventoryError("Unknown host probe")
    if probe == "wrapper" and not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise InventoryError("Missing trusted wrapper digest")
    if probe == "host" and expected_digest:
        raise InventoryError("Host readiness probe does not accept a digest")
    fixed = HOST_COMMAND if probe == "host" else WRAPPER_COMMAND
    assert_command_safe(fixed)
    # Fixed host identity, shape and plugin health validated before any command.
    compartment_id, instance_id = verified_run_command_host(sdk, config)
    models = sdk.compute_instance_agent.models
    command = models.InstanceAgentCommandContent(
        source=models.InstanceAgentCommandSourceViaTextDetails(text=fixed),
        output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT"),
    )
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment_id,
        execution_time_out_in_seconds=120,
        target=models.InstanceAgentCommandTarget(instance_id=instance_id),
        content=command,
        display_name=("shadowops-existing-a1-read-only-probe" if probe == "host"
                      else "shadowops-chronicles-wrapper-read-only-probe"),
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
            if probe == "wrapper":
                verdict = wrapper_verdict(output, expected_digest)
                print(verdict, flush=True)
                if verdict != "CHRONICLES_API_WRAPPER_CURRENT":
                    raise InventoryError("Installed Chronicles wrapper not current")
            else:
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
    assert_command_safe(WRAPPER_COMMAND)
    digest = "a" * 64
    assert wrapper_verdict("CHRONICLES_API_WRAPPER_SHA256 " + digest, digest) == "CHRONICLES_API_WRAPPER_CURRENT"
    print("SHADOWOPS_OCI_HOST_PROBE_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("run", "self-test", "wrapper"))
    args = parser.parse_args()
    if args.operation == "self-test":
        self_test()
        return 0
    try:
        import oci
        import os
        digest = local_wrapper_digest() if args.operation == "wrapper" else ""
        execute(oci, config_from_env(oci, os.environ),
                probe=("wrapper" if args.operation == "wrapper" else "host"),
                expected_digest=digest)
    except (InventoryError, Exception) as exc:
        # Fail closed without logging SDK exception details or remote output.
        print("SHADOWOPS_OCI_HOST_PROBE_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
