#!/usr/bin/env python3
"""Send only an admitted Chronicles API digest (+ the non-secret Vault OCID) to its
fixed root-owned wrapper.

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

from oci_control_plane import InventoryError, config_from_env, verified_run_command_host

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WRAPPER = "/usr/local/sbin/shadowops-chronicles-api"
VAULT = re.compile(r"^ocid1\.vault\.[A-Za-z0-9._-]{10,200}$")
MARKER = "CHRONICLES_API_OCI_STAGING_SMOKE_OK digest="
BLOCKED = re.compile(r"^CHRONICLES_API_OCI_DEPLOY_BLOCKED type=[A-Za-z]{1,40} reason=[A-Za-z0-9 ,./:()'_-]{0,120}$")
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}
HOST_TIMING_PREFIX = "CHRONICLES_API_OCI_HOST_PHASE_SECONDS "
HOST_TIMING_FIELDS = ("guard", "vault", "runtime", "compose", "pull", "recheck", "up", "smoke", "receipt")
HOST_TIMING = re.compile(
    "^" + HOST_TIMING_PREFIX +
    " ".join(field + r"=(?:0|[1-9][0-9]{0,4})" for field in HOST_TIMING_FIELDS) + "$"
)


def trusted_host_timing(remote_output: str) -> str:
    """Allowlist one bounded fixed-format timing line; never echo remote logs."""
    candidates = [line for line in remote_output.splitlines()
                  if line.startswith(HOST_TIMING_PREFIX)]
    if len(candidates) == 1 and HOST_TIMING.fullmatch(candidates[0]):
        return candidates[0]
    return ""



ENVIRONMENTS = ("staging", "production")


def marker_for(environment: str) -> str:
    return "CHRONICLES_API_OCI_" + environment.upper() + "_SMOKE_OK digest="


def command_for(digest: str, vault_id: str, environment: str = "staging") -> str:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise InventoryError("Invalid immutable Chronicles API digest")
    if not isinstance(vault_id, str) or not VAULT.fullmatch(vault_id):
        raise InventoryError("Invalid Vault OCID")
    if environment not in ENVIRONMENTS:
        raise InventoryError("Invalid environment")
    # Staging keeps the original 2-argument form (works with any installed wrapper).
    suffix = "" if environment == "staging" else " " + environment
    command = (
        "set -euo pipefail\n"
        "test -x " + WRAPPER + "\n"
        # stderr joins stdout so the wrapper's bounded BLOCKED reason (fixed,
        # authored strings only) can be surfaced; nothing else is ever echoed.
        "sudo --non-interactive " + WRAPPER + " deploy " + digest + " " + vault_id + suffix + " 2>&1\n"
    )
    if len(command.encode()) > 4096 or WRAPPER not in command:
        raise InventoryError("Chronicles API Run Command exceeds fixed policy")
    return command


def phase_timing(start: float, prepared: float, submitted: float, completed: float) -> str:
    """Safe fixed-label, whole-second timing; never output OCI IDs or secrets."""
    duration = lambda a, b: max(0, int(b - a))
    return ("CHRONICLES_API_OCI_PHASE_SECONDS "
            + f"preflight={duration(start, prepared)} "
            + f"dispatch={duration(prepared, submitted)} "
            + f"execution={duration(submitted, completed)}")


def execute(
    sdk: Any, config: dict[str, str], digest: str, environment: str = "staging", *,
    pause=time.sleep, clock=time.monotonic
) -> str:
    from chronicles_api_provision import resolve_vault
    started = clock()
    # Identity, shape and plugin are checked once, before any OCI mutation.
    compartment_id, instance_id = verified_run_command_host(sdk, config)
    vault_id, _key, _ = resolve_vault(sdk, config, compartment_id)
    fixed = command_for(digest, vault_id, environment)
    marker = marker_for(environment)
    prepared = clock()
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
        display_name="shadowops-chronicles-api-" + environment + "-release",
    )
    agent = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = agent.create_instance_agent_command(
        create_instance_agent_command_details=details,
    ).data
    command_id = str(getattr(created, "id", "") or "")
    if not command_id:
        raise InventoryError("Chronicles API deploy did not return an OCI command ID")
    submitted = clock()
    deadline = submitted + 650
    while clock() < deadline:
        execution = agent.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance_id,
        ).data
        status = str(getattr(execution, "lifecycle_state", "") or "").upper()
        if status in TERMINAL:
            result = getattr(execution, "content", None)
            stdout = str(getattr(result, "text", "") or "").strip()
            last = stdout.splitlines()[-1] if stdout else ""
            if (status != "SUCCEEDED" or getattr(result, "exit_code", None) != 0
                    or last != marker + digest):
                # Never echo Oracle's raw remote output: only the wrapper's own
                # bounded reason line, matched strictly.
                reason = next((line for line in stdout.splitlines() if BLOCKED.fullmatch(line)), "")
                raise InventoryError("Chronicles API root-wrapper smoke did not succeed"
                                     + (" | " + reason if reason else f" | status={status}"))
            timing = trusted_host_timing(stdout)
            if timing:
                print(timing, flush=True)
            print(phase_timing(started, prepared, submitted, clock()), flush=True)
            print(marker + digest)
            return last
        pause(3)
    raise InventoryError("Chronicles API OCI release timed out")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=False, default="")
    parser.add_argument("--environment", choices=ENVIRONMENTS, default="staging")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        sample = "sha256:" + "a" * 64
        command = command_for(sample, "ocid1.vault.oc1.eu-frankfurt-1.example")
        assert command.count("sudo --non-interactive ") == 1
        assert "docker " not in command and "chess-studio-deploy" not in command
        assert "MONGO" not in command and "TOKEN" not in command
        assert command_for(sample, "ocid1.vault.oc1.eu-frankfurt-1.example", "production").rstrip().endswith(" production 2>&1")
        print("SHADOWOPS_CHRONICLES_API_OCI_RELEASE_SELF_TEST_OK")
        return 0
    try:
        import oci
        execute(oci, config_from_env(oci, os.environ), args.digest, args.environment)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, InventoryError) else ""
        print("CHRONICLES_API_OCI_RELEASE_BLOCKED type=" + type(exc).__name__
              + (" detail=" + detail[:300] if detail else ""), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
