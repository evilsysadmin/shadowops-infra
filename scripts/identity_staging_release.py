#!/usr/bin/env python3
"""Send only an admitted digest/SHA/Vault ID to the installed staging-only wrapper."""
from __future__ import annotations
import os
import re
import sys
import time

from chronicles_api_provision import resolve_vault
from oci_control_plane import config_from_env, inspect, resolve_existing_host

WRAPPER='/usr/local/sbin/shadowops-identity-staging'
DIGEST=re.compile(r'sha256:[a-f0-9]{64}')
SHA=re.compile(r'[a-f0-9]{40}')
VAULT=re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')


class ReleaseError(ValueError):pass


def command_for(digest,sha,vault):
    if not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha) or not VAULT.fullmatch(vault):
        raise ReleaseError('Invalid immutable staging request')
    return 'set -eu\ntest -x '+WRAPPER+'\nsudo --non-interactive '+WRAPPER+' deploy '+digest+' '+sha+' '+vault+'\n'


def receipt(status,content,digest,sha):
    expected='IDENTITY_STAGING_SERVICE_STARTED source_sha='+sha+' digest='+digest
    output=str(getattr(content,'text','') or '').strip()
    if status != 'SUCCEEDED' or getattr(content,'exit_code',None) != 0 or output != expected:
        raise ReleaseError('Installed Identity wrapper did not return the admitted startup receipt')
    return expected


def execute(sdk,config,digest,sha,pause=time.sleep,clock=time.monotonic):
    # Validate before any cloud request; host/Vault cannot be selected by a caller.
    command_for(digest,sha,'ocid1.vault.oc1.eu.exampleidentifier')
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    vault,_,_=resolve_vault(sdk,config,compartment)
    command=command_for(digest,sha,vault)
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=600,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-admitted-release')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing release command receipt')
    deadline=clock()+780
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        status=str(getattr(execution,'lifecycle_state','')).upper()
        if status in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            return receipt(status,getattr(execution,'content',None),digest,sha)
        pause(3)
    raise ReleaseError('Identity staging release timed out')


def main():
    try:
        import oci
        print(execute(oci,config_from_env(oci,os.environ),os.environ.get('ADMITTED_DIGEST',''),os.environ.get('ADMITTED_SHA','')))
    except Exception as exc:
        print('IDENTITY_STAGING_RELEASE_BLOCKED type='+type(exc).__name__,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
