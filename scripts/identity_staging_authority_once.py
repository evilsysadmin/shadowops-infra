#!/usr/bin/env python3
"""One-use read-only inventory of existing staging Identity bootstrap authority.

No install, sudo grant, group change, workload mutation, secret read or host output dump.
Remove the credential-backed workflow after recording its sanitized receipt.
"""
from __future__ import annotations
import os
import re
import sys
import time

from oci_control_plane import config_from_env, inspect, resolve_existing_host

COMMAND = r'''set -eu
export LC_ALL=C
test "$(uname -m)" = aarch64
if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then docker=yes; else docker=no; fi
if test -x /usr/local/sbin/shadowops-identity-staging; then identity_wrapper=yes; else identity_wrapper=no; fi
if test -d /opt/shadowops-infra/.git; then repo=yes; else repo=no; fi
# Observe existing policy only. Never execute a root shell or grant privileges.
identity_sudo_rules="$(sudo --non-interactive -l 2>/dev/null || true)"
if printf '%s\n' "$identity_sudo_rules" | grep -Eq '\(ALL( : ALL)?\) NOPASSWD: ALL([[:space:]]|$)'; then operator_sudo=yes; else operator_sudo=no; fi
unset identity_sudo_rules
printf 'IDENTITY_STAGING_AUTHORITY docker=%s identity_wrapper=%s repo=%s operator_sudo=%s\n' "$docker" "$identity_wrapper" "$repo" "$operator_sudo"
'''
RECEIPT = re.compile(r'IDENTITY_STAGING_AUTHORITY docker=(yes|no) identity_wrapper=(yes|no) repo=(yes|no) operator_sudo=(yes|no)')
TERMINAL={'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}


class AuthorityError(ValueError):
    pass


def receipt(status, content):
    output=str(getattr(content,'text','') or '').strip()
    if status != 'SUCCEEDED' or getattr(content,'exit_code',None) != 0 or not RECEIPT.fullmatch(output):
        raise AuthorityError('Untrusted staging authority receipt')
    return output


def run(sdk, config, pause=time.sleep, clock=time.monotonic):
    inspect(sdk, config)
    compartment, instance=resolve_existing_host(sdk, config)
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment, execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(
            source=models.InstanceAgentCommandSourceViaTextDetails(text=COMMAND),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-authority-once')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    command=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(command,'id',None):
        raise AuthorityError('Missing command receipt')
    deadline=clock()+360
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(
            instance_agent_command_id=command.id, instance_id=instance).data
        status=str(getattr(execution,'lifecycle_state','')).upper()
        if status in TERMINAL:
            return receipt(status,getattr(execution,'content',None))
        pause(2)
    raise AuthorityError('Authority inventory timed out')


def main():
    try:
        import oci
        print(run(oci,config_from_env(oci,os.environ)))
    except Exception as exc:
        print('IDENTITY_STAGING_AUTHORITY_BLOCKED type='+type(exc).__name__,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
