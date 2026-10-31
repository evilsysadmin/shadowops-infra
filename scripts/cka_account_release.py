#!/usr/bin/env python3
"""OCI transport for the fixed, operator-installed CKA account policy only."""
import argparse
import os
import re
import time
from cka_account_contract import AccountError, DIGEST, SHA, VAULT
from chronicles_api_provision import resolve_vault
from oci_control_plane import config_from_env, inspect, resolve_existing_host

WRAPPER='/usr/local/sbin/shadowops-cka-account-staging'

def command_for(operation,digest='',sha='',vault=''):
    if operation in {'inspect','stop'} and not any((digest,sha,vault)):
        args=operation
    elif operation=='deploy' and DIGEST.fullmatch(digest) and SHA.fullmatch(sha) and VAULT.fullmatch(vault):
        args='deploy '+digest+' '+sha+' '+vault
    else:raise AccountError('Invalid fixed CKA account command')
    return 'set -euo pipefail\ntest -x '+WRAPPER+'\nsudo --non-interactive '+WRAPPER+' '+args+'\n'

def receipt(state,content,operation,digest='',sha=''):
    output=str(getattr(content,'text','') or '').strip()
    if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0:raise AccountError('CKA root policy command failed')
    # OCI sometimes omits text even with an authoritative successful exit code.
    # For deploy, this is command completion only; mandatory public checks follow.
    if not output:return 'CKA_ACCOUNT_'+operation.upper()+'_COMMAND_COMPLETED'
    if operation=='stop' and output=='CKA_ACCOUNT_STAGING_STOPPED':return 'CKA_ACCOUNT_STAGING_STOPPED'
    if operation=='inspect' and re.fullmatch(r'CKA_ACCOUNT_STAGING_POLICY_OK source_sha=[a-f0-9]{40}',output):
        return 'CKA_ACCOUNT_POLICY_VERIFIED'
    if operation=='deploy' and output=='CKA_ACCOUNT_STAGING_STARTED source_sha='+sha+' digest='+digest:
        return 'CKA_ACCOUNT_DEPLOY_COMMAND_COMPLETED'
    raise AccountError('CKA root policy receipt mismatch')

def execute(sdk,config,operation,digest='',sha='',pause=time.sleep,clock=time.monotonic):
    if operation in {'inspect','stop'}:command_for(operation)
    elif operation=='deploy':command_for(operation,digest,sha,'ocid1.vault.oc1.eu.exampleidentifier')
    else:raise AccountError('Invalid account operation')
    inspect(sdk,config);compartment,instance=resolve_existing_host(sdk,config)
    vault=resolve_vault(sdk,config,compartment)[0] if operation=='deploy' else ''
    fixed=command_for(operation,digest,sha,vault if operation=='deploy' else '')
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,execution_time_out_in_seconds=600,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=fixed),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='cka-account-staging-'+operation)
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise AccountError('Missing CKA command ID')
    deadline=clock()+780
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            return receipt(state,getattr(execution,'content',None),operation,digest,sha)
        pause(3)
    raise AccountError('CKA account command timed out')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('operation',choices=['inspect','deploy','stop'])
    parser.add_argument('--digest',default='');parser.add_argument('--sha',default='');args=parser.parse_args()
    try:
        import oci
        print(execute(oci,config_from_env(oci,os.environ),args.operation,args.digest,args.sha));return 0
    except Exception as error:
        print('CKA_ACCOUNT_RELEASE_BLOCKED type='+type(error).__name__);return 1
if __name__=='__main__':raise SystemExit(main())
