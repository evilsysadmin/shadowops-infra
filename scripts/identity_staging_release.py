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


def failure_reason(output):
    marker = next((line for line in output.splitlines() if re.fullmatch(r'IDENTITY_STAGING_DEPLOY_BLOCKED type=[A-Za-z]{1,40}',line)),None)
    if marker:
        return marker
    if re.fullmatch(r'IDENTITY_STAGING_SERVICE_STARTED source_sha=[a-f0-9]{40} digest=sha256:[a-f0-9]{64}',output.strip()):
        return 'startup-receipt'
    if 'sudo:' in output:
        return 'wrapper-permission-denied'
    if 'ModuleNotFoundError:' in output or 'ImportError:' in output:
        return 'wrapper-import-failed'
    return 'no-wrapper-receipt'


def receipt(status,content,digest,sha):
    expected='IDENTITY_STAGING_SERVICE_STARTED source_sha='+sha+' digest='+digest
    output=str(getattr(content,'text','') or '').strip()
    if status != 'SUCCEEDED' or getattr(content,'exit_code',None) != 0 or output != expected:
        reason = failure_reason(output)
        state = status if status in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'} else 'UNKNOWN'
        raise ReleaseError('status='+state+' reason='+reason)
    return expected


def inspect_previous(sdk,config):
    compartment,instance=resolve_existing_host(sdk,config)
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    # Read only the latest bounded execution page on the adopted host. No new
    # command is submitted; command IDs, private output and other jobs stay private.
    rows=client.list_instance_agent_command_executions(compartment_id=compartment,instance_id=instance,
        limit=25,sort_by='TIMECREATED',sort_order='DESC').data
    for row in rows:
        if getattr(row,'display_name','') != 'identity-staging-admitted-release' or getattr(row,'instance_id','') != instance:
            continue
        state=str(getattr(row,'lifecycle_state','')).upper()
        if state not in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED','ACCEPTED','IN_PROGRESS'}:
            state='UNKNOWN'
        output=str(getattr(getattr(row,'content',None),'text','') or '')
        return 'IDENTITY_STAGING_PREVIOUS_RELEASE status='+state+' reason='+failure_reason(output)
    raise ReleaseError('No recent Identity release receipt on the adopted host')


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
        config=config_from_env(oci,os.environ)
        if sys.argv[1:]==['inspect']:
            print(inspect_previous(oci,config))
        elif sys.argv[1:]:
            raise ReleaseError('Invalid release operation')
        else:
            print(execute(oci,config,os.environ.get('ADMITTED_DIGEST',''),os.environ.get('ADMITTED_SHA','')))
    except Exception as exc:
        detail = ' '+str(exc) if isinstance(exc,ReleaseError) else ''
        print('IDENTITY_STAGING_RELEASE_BLOCKED type='+type(exc).__name__+detail,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
