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


def observed_lifecycle_timing(submitted: float, first_active: float | None,
                              completed: float) -> str:
    """Monotonic *observations*, not exact OCI scheduling or host runtimes.

    OCI may transition between 3-second polls, or go straight to terminal.
    Without an observed IN_PROGRESS do not claim to know the queue split.
    """
    if first_active is None:
        return ""
    duration = lambda a, b: min(99999, max(0, int(b - a)))
    return ("CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS "
            + f"pre_active={duration(submitted, first_active)} "
            + f"active={duration(first_active, completed)}")

def observed_delivery_timing(submitted: float, first_acked: float | None,
                             completed: float) -> str:
    """Only an ACKED status seen before terminal; never infer actual start."""
    if first_acked is None:
        return ""
    duration = lambda a, b: min(99999, max(0, int(b - a)))
    return ("CHRONICLES_API_OCI_DELIVERY_OBSERVED_SECONDS "
            + f"before_ack={duration(submitted, first_acked)} "
            + f"after_ack={duration(first_acked, completed)}")


def observed_poll_timing(calls: int, total: float, slowest: float) -> str:
    """Local OCI GET round-trip durations, never host execution time."""
    if calls <= 0:
        return ""
    bounded = lambda n: min(99999, max(0, int(n)))
    return ("CHRONICLES_API_OCI_POLL_SECONDS "
            + f"calls={bounded(calls)} total={bounded(total)} "
            + f"slowest={bounded(slowest)}")


def observed_poll_detail_timing(pre_calls: int, pre_seconds: float,
                                post_calls: int, post_seconds: float,
                                slowest_seconds: float) -> str:
    """Local GET wall time by ACK observation; never exact delivery time.

    The GET that first observes ACKED is pre_ack. Without nonterminal ACKED,
    all GETs count as pre_ack and post_ack stays zero.
    """
    bounded_count = lambda n: min(99999, max(0, int(n)))
    bounded_ms = lambda n: min(999999, max(0, int(n * 1000)))
    return ("CHRONICLES_API_OCI_POLL_DETAIL_MS "
            + f"pre_ack_calls={bounded_count(pre_calls)} "
            + f"pre_ack_ms={bounded_ms(pre_seconds)} "
            + f"post_ack_calls={bounded_count(post_calls)} "
            + f"post_ack_ms={bounded_ms(post_seconds)} "
            + f"slowest_ms={bounded_ms(slowest_seconds)}")


# Summary contents are assembled exclusively from local, fixed-format
# controller timings plus the strictly admitted host timing. Never interpolate
# arbitrary OCI stdout, command IDs, Vault IDs, digests or failure reasons.
PHASE_LINE = re.compile(
    r"CHRONICLES_API_OCI_PHASE_SECONDS preflight=[0-9]{1,5} dispatch=[0-9]{1,5} execution=[0-9]{1,5}"
)
LIFECYCLE_LINE = re.compile(
    r"CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=[0-9]{1,5} active=[0-9]{1,5}"
)
DELIVERY_LINE = re.compile(
    r"CHRONICLES_API_OCI_DELIVERY_OBSERVED_SECONDS before_ack=[0-9]{1,5} after_ack=[0-9]{1,5}"
)
POLL_LINE = re.compile(
    r"CHRONICLES_API_OCI_POLL_SECONDS calls=[0-9]{1,5} total=[0-9]{1,5} slowest=[0-9]{1,5}"
)
POLL_DETAIL_LINE = re.compile(
    r"CHRONICLES_API_OCI_POLL_DETAIL_MS pre_ack_calls=[0-9]{1,5} "
    r"pre_ack_ms=[0-9]{1,6} post_ack_calls=[0-9]{1,5} "
    r"post_ack_ms=[0-9]{1,6} slowest_ms=[0-9]{1,6}"
)


def timing_summary(phase: str, lifecycle: str = "", host: str = "",
                   *, verified: bool, delivery: str = "", poll: str = "",
                   poll_detail: str = "") -> str:
    """Render only finite validated lines; optional host timing is not guessed."""
    if not PHASE_LINE.fullmatch(phase):
        return ""
    if lifecycle and not LIFECYCLE_LINE.fullmatch(lifecycle):
        return ""
    if delivery and not DELIVERY_LINE.fullmatch(delivery):
        return ""
    if poll and not POLL_LINE.fullmatch(poll):
        return ""
    if poll_detail and not POLL_DETAIL_LINE.fullmatch(poll_detail):
        return ""
    if host and not HOST_TIMING.fullmatch(host):
        return ""
    result = [
        "### Chronicles API · OCI deployment timing",
        "",
        "- Verified wrapper smoke: " + ("yes" if verified else "no"),
        "- Controller phases: " + "`" + phase + "`",
        "- OCI lifecycle observation: " + (
            "`" + lifecycle + "`" if lifecycle
            else "not observed; no queue/active split inferred"),
        "- OCI agent delivery acknowledgement: " + (
            "`" + delivery + "`" if delivery
            else "not observed before terminal; no delivery delay inferred"),
        "- OCI GET round trips (local controller): " + (
            "`" + poll + "`" if poll else "not measured"),
        "- OCI GET latency around observed ACK (local milliseconds): " + (
            "`" + poll_detail + "`" if poll_detail else "not measured"),
        "- Installed wrapper phases: " + (
            "`" + host + "`" if host
            else "not reported (does not prove the wrapper is outdated)"),
        "",
        "ACKED means the agent received the command, not that execution started. "
        "All observations are taken at polling boundaries, not exact timings. "
        "The GET that first observes ACKED is pre_ack; without a nonterminal "
        "ACKED, post_ack remains zero.",
        "",
    ]
    return "\n".join(result)


def append_timing_summary(phase: str, lifecycle: str = "", host: str = "",
                          *, verified: bool, path: str | None = None,
                          delivery: str = "", poll: str = "",
                          poll_detail: str = "") -> None:
    """Optional Actions UX only: summary write failures never alter admission."""
    destination = os.environ.get("GITHUB_STEP_SUMMARY", "") if path is None else path
    if not destination:
        return
    summary = timing_summary(phase, lifecycle, host, verified=verified,
                             delivery=delivery, poll=poll, poll_detail=poll_detail)
    if not summary:
        return
    try:
        with open(destination, "a", encoding="utf-8") as output:
            output.write(summary)
    except OSError:
        # Diagnostic formatting must not make a verified deployment fail.
        pass

def execute(
    sdk: Any, config: dict[str, str], digest: str, environment: str = "staging", *,
    pause=time.sleep, clock=time.monotonic, poll_clock=time.monotonic
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
    first_active = None
    first_acked = None
    poll_calls, poll_total, poll_slowest = 0, 0.0, 0.0
    pre_ack_calls, pre_ack_elapsed = 0, 0.0
    post_ack_calls, post_ack_elapsed = 0, 0.0
    while clock() < deadline:
        poll_start = poll_clock()
        execution = agent.get_instance_agent_command_execution(
            instance_agent_command_id=command_id, instance_id=instance_id,
        ).data
        elapsed = max(0.0, poll_clock() - poll_start)
        poll_calls += 1
        poll_total += elapsed
        poll_slowest = max(poll_slowest, elapsed)
        if first_acked is None:
            pre_ack_calls += 1
            pre_ack_elapsed += elapsed
        else:
            post_ack_calls += 1
            post_ack_elapsed += elapsed
        status = str(getattr(execution, "lifecycle_state", "") or "").upper()
        # ACKED means delivery to the agent; it does not prove execution.
        # Terminal ACKED alone has no usable timestamp, so ignore it.
        if (status not in TERMINAL and first_acked is None
                and getattr(execution, "delivery_state", "") == "ACKED"):
            first_acked = clock()
        if status == "IN_PROGRESS" and first_active is None:
            first_active = clock()
        if status in TERMINAL:
            completed = clock()
            lifecycle = observed_lifecycle_timing(submitted, first_active, completed)
            delivery = observed_delivery_timing(submitted, first_acked, completed)
            poll = observed_poll_timing(poll_calls, poll_total, poll_slowest)
            poll_detail = observed_poll_detail_timing(
                pre_ack_calls, pre_ack_elapsed, post_ack_calls, post_ack_elapsed, poll_slowest)
            if lifecycle:
                print(lifecycle, flush=True)
            if delivery:
                print(delivery, flush=True)
            if poll:
                print(poll, flush=True)
            print(poll_detail, flush=True)
            result = getattr(execution, "content", None)
            stdout = str(getattr(result, "text", "") or "").strip()
            last = stdout.splitlines()[-1] if stdout else ""
            phase = phase_timing(started, prepared, submitted, completed)
            if (status != "SUCCEEDED" or getattr(result, "exit_code", None) != 0
                    or last != marker + digest):
                # Never echo Oracle's raw remote output: only the wrapper's own
                # bounded reason line, matched strictly.
                reason = next((line for line in stdout.splitlines() if BLOCKED.fullmatch(line)), "")
                print(phase, flush=True)
                append_timing_summary(phase, lifecycle, verified=False,
                                      delivery=delivery, poll=poll, poll_detail=poll_detail)
                raise InventoryError("Chronicles API root-wrapper smoke did not succeed"
                                     + (" | " + reason if reason else f" | status={status}"))
            timing = trusted_host_timing(stdout)
            if timing:
                print(timing, flush=True)
            print(phase, flush=True)
            append_timing_summary(phase, lifecycle, timing, verified=True,
                                  delivery=delivery, poll=poll, poll_detail=poll_detail)
            print(marker + digest)
            return last
        pause(3)
    # A non-terminal OCI wait is precisely when the controller's timings are
    # most useful. Do not claim a successful smoke or infer unobserved states.
    # All values come from the local monotonic clock, never remote stdout.
    completed = clock()
    lifecycle = observed_lifecycle_timing(submitted, first_active, completed)
    delivery = observed_delivery_timing(submitted, first_acked, completed)
    poll = observed_poll_timing(poll_calls, poll_total, poll_slowest)
    poll_detail = observed_poll_detail_timing(
        pre_ack_calls, pre_ack_elapsed, post_ack_calls, post_ack_elapsed, poll_slowest)
    if lifecycle:
        print(lifecycle, flush=True)
    if delivery:
        print(delivery, flush=True)
    if poll:
        print(poll, flush=True)
    print(poll_detail, flush=True)
    phase = phase_timing(started, prepared, submitted, completed)
    print(phase, flush=True)
    append_timing_summary(phase, lifecycle, verified=False, delivery=delivery,
                          poll=poll, poll_detail=poll_detail)
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
