#!/usr/bin/env python3
"""Fixed, nonprivileged readiness observation for CKA Compose on the adopted A1."""
from __future__ import annotations

import json
import math
import os
import sys
import time

from oci_control_plane import InventoryError, config_from_env, inspect, resolve_existing_host

MARKER = "CKA_SHARED_LAB_HOST "
# No provider credentials, Docker metadata, host identifiers or user-selected
# commands are read. sudo -l observes policy only; it never executes as root.
PROBE = r'''
import json,os,platform,re,shutil,subprocess
from pathlib import Path
if platform.machine() != 'aarch64':raise SystemExit(1)
memory={line.split(':')[0]:int(line.split()[1])//1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
disk=os.statvfs('/var/lib')
def available(name):return shutil.which(name) is not None
def integer(path):
 try:return int(Path(path).read_text().strip())
 except (ValueError,OSError):return 0
try:
 rules=subprocess.run(['sudo','--non-interactive','-l'],capture_output=True,text=True,timeout=5)
 operator=rules.returncode==0 and len(rules.stdout)<16384 and re.search(r'\(ALL(?: : ALL)?\) NOPASSWD: ALL(?:\s|$)',rules.stdout) is not None
except (OSError,subprocess.TimeoutExpired):operator=False
value={'schema':1,'cpus':os.cpu_count(),'memory_total_mib':memory['MemTotal'],'memory_available_mib':memory['MemAvailable'],'disk_available_mib':disk.f_bavail*disk.f_frsize//1048576,'load_1m':os.getloadavg()[0],'cgroup_v2':Path('/sys/fs/cgroup/cgroup.controllers').is_file(),'user_namespaces':integer('/proc/sys/user/max_user_namespaces')>0,'rootless_dockerd':available('dockerd-rootless.sh'),'rootlesskit':available('rootlesskit'),'newuidmap':available('newuidmap'),'newgidmap':available('newgidmap'),'slirp4netns':available('slirp4netns'),'operator_sudo':operator,'lab_wrapper':os.access('/usr/local/sbin/shadowops-cka-lab-staging',os.X_OK)}
print('CKA_SHARED_LAB_HOST '+json.dumps(value,sort_keys=True))
'''
COMMAND = "set -eu\npython3 -I - <<'CKA_FIXED_PREFLIGHT'\n" + PROBE + "\nCKA_FIXED_PREFLIGHT\n"
NUMBERS = {"cpus", "memory_total_mib", "memory_available_mib", "disk_available_mib"}
FLAGS = {"cgroup_v2", "user_namespaces", "rootless_dockerd", "rootlesskit", "newuidmap",
         "newgidmap", "slirp4netns", "operator_sudo", "lab_wrapper"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("Duplicate host observation field")
        result[key] = value
    return result


def receipt(state, content):
    raw = getattr(content, "text", None)
    if (state != "SUCCEEDED" or type(getattr(content, "exit_code", None)) is not int
            or content.exit_code != 0 or not isinstance(raw, str) or len(raw) > 4096):
        raise InventoryError("Shared lab host observation failed")
    raw = raw.strip()
    if not raw.startswith(MARKER):
        raise InventoryError("Shared lab host evidence missing")
    try:
        value = json.loads(raw[len(MARKER):], object_pairs_hook=unique_object)
    except (ValueError, TypeError):
        raise InventoryError("Shared lab host evidence malformed") from None
    if (not isinstance(value, dict) or set(value) != NUMBERS | FLAGS | {"schema", "load_1m"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or any(type(value[key]) is not bool for key in FLAGS)
            or any(type(value[key]) is not int or not 0 <= value[key] <= 2**40 for key in NUMBERS)
            or value["cpus"] < 1 or value["memory_total_mib"] < 1
            or value["memory_available_mib"] > value["memory_total_mib"]
            or type(value["load_1m"]) not in (int, float)
            or not math.isfinite(value["load_1m"]) or value["load_1m"] < 0):
        raise InventoryError("Shared lab host evidence invalid")
    return {**value, "resource_headroom": value["memory_available_mib"] >= 3072
            and value["disk_available_mib"] >= 12288,
            "pilot_enabled": False, "host_mutated": False}


def execute(sdk, config, *, pause=time.sleep, clock=time.monotonic):
    inspect(sdk, config)
    compartment, instance = resolve_existing_host(sdk, config)
    models = sdk.compute_instance_agent.models
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment, execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(
            source=models.InstanceAgentCommandSourceViaTextDetails(text=COMMAND),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type="TEXT")),
        display_name="cka-shared-compose-fixed-preflight")
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created, "id", None):
        raise InventoryError("Missing host observation reference")
    deadline = clock() + 360
    while clock() < deadline:
        execution = client.get_instance_agent_command_execution(
            instance_agent_command_id=created.id, instance_id=instance).data
        state = str(getattr(execution, "lifecycle_state", "")).upper()
        if state in {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}:
            return receipt(state, getattr(execution, "content", None))
        pause(2)
    raise InventoryError("Shared lab host observation timed out")


def main():
    try:
        import oci
        result = execute(oci, config_from_env(oci, os.environ))
    except Exception:
        print("CKA_SHARED_LAB_PREFLIGHT_BLOCKED: no verified host evidence", file=sys.stderr)
        return 1
    print("CKA_SHARED_LAB_PREFLIGHT " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
