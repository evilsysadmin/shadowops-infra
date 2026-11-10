#!/usr/bin/env python3
"""Send only an admitted digest/SHA/Vault ID to the installed staging-only wrapper."""
from __future__ import annotations
import os
import hashlib
from pathlib import Path
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


# These fixed labels are emitted only by the root-owned installed wrapper.
# A malicious/compromised remote output must never echo arbitrary text to CI.
DEPLOY_PHASES = frozenset((
    'source', 'custody', 'images', 'database-start',
    'database-ready', 'database-bootstrap', 'services-start',
    'custody-atlas', 'custody-host', 'custody-identity',
    'custody-vault', 'custody-backup', 'custody-config',
))
DEPLOY_BLOCKED = re.compile(
    r'IDENTITY_STAGING_DEPLOY_BLOCKED type=[A-Za-z]{1,40}(?: phase=([a-z-]{1,32}))?\Z'
)


def failure_reason(output):
    for line in output.splitlines():
        match = DEPLOY_BLOCKED.fullmatch(line)
        if match and (match.group(1) is None or match.group(1) in DEPLOY_PHASES):
            return line
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
    if status == 'SUCCEEDED' and getattr(content,'exit_code',None) == 0 and not output:
        # OCI can omit command text. This acknowledges transport completion
        # only: the caller must still prove live HTTPS readiness and exact SHA.
        return 'IDENTITY_STAGING_COMMAND_COMPLETED source_sha='+sha+' digest='+digest+' public_verification=required'
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
        command_id=getattr(row,'instance_agent_command_id','')
        if not command_id:
            raise ReleaseError('Missing previous command reference')
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=command_id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state not in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED','ACCEPTED','IN_PROGRESS'}:
            state='UNKNOWN'
        content=getattr(execution,'content',None)
        output=str(getattr(content,'text','') or '')
        code=getattr(content,'exit_code',None)
        code=str(code) if type(code) is int and -255 <= code <= 255 else 'missing'
        return 'IDENTITY_STAGING_PREVIOUS_RELEASE status='+state+' exit='+code+' lines='+str(len(output.splitlines()))+' reason='+failure_reason(output)
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



def execute_backup(sdk,config,pause=time.sleep,clock=time.monotonic):
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    vault,_,_=resolve_vault(sdk,config,compartment)
    if not VAULT.fullmatch(vault):raise ReleaseError('Invalid fixed backup custody')
    wrapper='/usr/local/sbin/shadowops-identity-staging-backup'
    command='set -eu\ntest -x '+wrapper+'\nsudo --non-interactive '+wrapper+' backup '+vault+'\n'
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=300,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-encrypted-backup')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing backup command reference')
    deadline=clock()+480
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0:
                raise ReleaseError('Fixed encrypted backup did not complete')
            # OCI may omit stdout. Native activation independently requires the
            # fresh root-owned last-backup.json written only after encryption.
            return 'IDENTITY_STAGING_BACKUP_COMMAND_COMPLETED activation_receipt=required'
        pause(3)
    raise ReleaseError('Identity backup timed out')

def execute_atlas_prepare(sdk,config,pause=time.sleep,clock=time.monotonic,mode='strict'):
    if mode not in {'strict','database-scoped','refresh-inventory','check-inventory-inactive'}:raise ReleaseError('Invalid Atlas privilege mode')
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    vault,_,_=resolve_vault(sdk,config,compartment)
    if not VAULT.fullmatch(vault):raise ReleaseError('Invalid fixed Atlas custody')
    wrapper='/usr/local/sbin/shadowops-identity-atlas-prepare'
    operation={'strict':'prepare','database-scoped':'prepare-database-scoped','refresh-inventory':'refresh-inventory','check-inventory-inactive':'check-inventory-inactive'}[mode]
    command='set -eu\ntest -x '+wrapper+'\nsudo --non-interactive '+wrapper+' '+operation+' '+vault+'\n'
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=300,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-prepare')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing Atlas prepare command reference')
    deadline=clock()+480
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0:
                raise ReleaseError('Fixed Atlas configuration preparation did not complete')
            output=str(getattr(content,'text','') or '').strip()
            if (mode == 'check-inventory-inactive' and output != 'IDENTITY_ATLAS_STAGING_CONFIG_PREPARED') or (output and output != 'IDENTITY_ATLAS_STAGING_CONFIG_PREPARED'):
                raise ReleaseError('Unexpected Atlas preparation receipt')
            return 'IDENTITY_ATLAS_PREPARE_COMMAND_COMPLETED preflight=required'
        pause(3)
    raise ReleaseError('Atlas configuration preparation timed out')

def execute_atlas_snooker_config(sdk,config,pause=time.sleep,clock=time.monotonic):
    """Stage a separate, never-mounted candidate config; no service mutation."""
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    vault,_,_=resolve_vault(sdk,config,compartment)
    if not VAULT.fullmatch(vault):
        raise ReleaseError('Invalid fixed staging Vault custody')
    wrapper='/usr/local/sbin/shadowops-identity-atlas-snooker-config'
    command='set -eu\ntest -x '+wrapper+'\nsudo --non-interactive '+wrapper+' stage '+vault+'\n'
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment,execution_time_out_in_seconds=300,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(
            source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-snooker-config-stage')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):
        raise ReleaseError('Missing protected candidate staging command')
    deadline=clock()+480
    pattern=re.compile(r'IDENTITY_ATLAS_SNOOKER_CONFIG_STAGED result=(created|already-matching) previous_config=unchanged local_source=unchanged deploy=not-attempted\Z')
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(
            instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            output=str(getattr(getattr(execution,'content',None),'text','') or '').strip()
            if (state!='SUCCEEDED'
                or getattr(getattr(execution,'content',None),'exit_code',None)!=0
                or not pattern.fullmatch(output)):
                # Never print OCI execution text or the Vault ID.
                raise ReleaseError('Snooker Atlas candidate stage not verified')
            return 'IDENTITY_ATLAS_SNOOKER_CONFIG_COMMAND_COMPLETED legacy=unchanged activation=not-attempted'
        pause(3)
    raise ReleaseError('Snooker Atlas candidate stage timed out')


def execute_atlas_preflight(sdk,config,digest,sha,pause=time.sleep,clock=time.monotonic):
    if not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha):
        raise ReleaseError('Invalid Atlas preflight source')
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    wrapper='/usr/local/sbin/shadowops-identity-atlas-preflight'
    command='set -eu\ntest -x '+wrapper+'\nsudo --non-interactive '+wrapper+' preflight '+digest+' '+sha+'\n'
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=300,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-preflight')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing Atlas preflight command reference')
    deadline=clock()+480
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            expected='IDENTITY_ATLAS_PREFLIGHT_OK source_sha='+sha+' digest='+digest
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0 or str(getattr(content,'text','') or '').strip()!=expected:
                raise ReleaseError('Atlas preflight did not return the exact receipt')
            return expected
        pause(3)
    raise ReleaseError('Atlas preflight timed out')

CANARY_SOURCES = {
    'host/identity-atlas-staging-canary.py': ('/usr/local/sbin/shadowops-identity-atlas-canary', '755'),
    'host/identity-atlas-staging-preflight.py': ('/usr/local/sbin/shadowops-identity-atlas-preflight', '755'),
    'scripts/identity_staging_atlas_journey.py': ('/usr/local/lib/shadowops/identity_staging_atlas_journey.py', '644'),
    'scripts/identity_staging_atlas_admission.py': ('/usr/local/lib/shadowops/identity_staging_atlas_admission.py', '644'),
    'scripts/identity_staging_atlas_backup.py': ('/usr/local/lib/shadowops/identity_staging_atlas_backup.py', '644'),
    'scripts/identity_staging_atlas.py': ('/usr/local/lib/shadowops/identity_staging_atlas.py', '644'),
    'scripts/identity_staging_backup.py': ('/usr/local/lib/shadowops/identity_staging_backup.py', '644'),
}


def canary_source_digests(root=None, sources=None):
    """Hash only fixed code from the trusted protected-main checkout."""
    root=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    result={}
    for source in (CANARY_SOURCES if sources is None else sources):
        path=root/source
        if path.is_symlink() or not path.is_file() or path.stat().st_size>1048576:
            raise ReleaseError('Invalid canary source checkout')
        result[source]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def installed_source_guard(sources,hashes):
    if not isinstance(hashes,dict) or set(hashes)!=set(sources) or any(not isinstance(v,str) or not re.fullmatch(r'[a-f0-9]{64}',v) for v in hashes.values()):
        raise ReleaseError('Invalid installed source digests')
    command='set -eu\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n'
    for directory in ('/usr/local','/usr/local/sbin','/usr/local/lib','/usr/local/lib/shadowops'):
        command+='test -d '+directory+' && test ! -L '+directory+' && test "$(stat -c %u:%a '+directory+')" = 0:755\n'
    for source,(target,mode_bits) in sources.items():
        command+='test -f '+target+' && test ! -L '+target+' && test "$(stat -c %u:%a '+target+')" = 0:'+mode_bits+'\n'
        command+="printf '%s  %s\\n' "+hashes[source]+' '+target+' | sha256sum --check --status\n'
    return command


def canary_host_command(mode,digest,sha,hashes):
    if mode not in {'canary','journey'} or not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha):
        raise ReleaseError('Invalid Atlas canary request')
    if not isinstance(hashes,dict) or set(hashes)!=set(CANARY_SOURCES) or any(not isinstance(v,str) or not re.fullmatch(r'[a-f0-9]{64}',v) for v in hashes.values()):
        raise ReleaseError('Invalid Atlas canary source digests')
    command=installed_source_guard(CANARY_SOURCES,hashes)
    command+='sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-canary '+mode+' '+digest+' '+sha+'\n'
    return command


def execute_atlas_canary(sdk,config,digest,sha,pause=time.sleep,clock=time.monotonic,mode="canary"):
    if mode not in {"canary", "journey"}:
        raise ReleaseError("Invalid Atlas canary operation")
    if not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha):
        raise ReleaseError('Invalid Atlas canary source')
    command=canary_host_command(mode,digest,sha,canary_source_digests())
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=900,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-'+mode)
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing Atlas canary command reference')
    deadline=clock()+1020
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            marker='IDENTITY_ATLAS_ADMIN_CANARY_OK' if mode=='journey' else 'IDENTITY_ATLAS_LOOPBACK_CANARY_OK'
            expected=marker+' source_sha='+sha+' digest='+digest
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0 or str(getattr(content,'text','') or '').strip()!=expected:
                raise ReleaseError('Atlas canary did not return the exact receipt')
            return expected
        pause(3)
    raise ReleaseError('Atlas canary timed out')

def execute_atlas_backup(sdk,config,pause=time.sleep,clock=time.monotonic):
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    wrapper='/usr/local/sbin/shadowops-identity-atlas-backup'
    command='set -eu\ntest -x '+wrapper+'\nsudo --non-interactive '+wrapper+' backup\n'
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=300,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-encrypted-backup')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing Atlas backup command reference')
    deadline=clock()+480
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            output=str(getattr(content,'text','') or '').strip()
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0 or not re.fullmatch(r'IDENTITY_ATLAS_STAGING_BACKUP_OK encrypted_bytes=[1-9][0-9]{0,8}',output):
                raise ReleaseError('Atlas encrypted backup receipt missing')
            return output
        pause(3)
    raise ReleaseError('Atlas backup timed out')

RESTORE_SOURCES = {
    'host/identity-atlas-staging-backup.py': ('/usr/local/sbin/shadowops-identity-atlas-backup', '755'),
    'scripts/identity_staging_atlas_restore.py': ('/usr/local/lib/shadowops/identity_staging_atlas_restore.py', '644'),
    **{source:CANARY_SOURCES[source] for source in (
        'scripts/identity_staging_atlas_admission.py',
        'scripts/identity_staging_atlas_backup.py',
        'scripts/identity_staging_backup.py')},
}


def execute_atlas_restore_rehearsal(sdk,config,pause=time.sleep,clock=time.monotonic):
    command=installed_source_guard(RESTORE_SOURCES,canary_source_digests(sources=RESTORE_SOURCES))
    command+='sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-backup rehearse\n'
    inspect(sdk,config)
    compartment,instance=resolve_existing_host(sdk,config)
    models=sdk.compute_instance_agent.models
    details=models.CreateInstanceAgentCommandDetails(compartment_id=compartment,
        execution_time_out_in_seconds=600,target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-restore-rehearsal')
    client=sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created=client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not getattr(created,'id',None):raise ReleaseError('Missing restore command reference')
    deadline=clock()+720
    while clock()<deadline:
        execution=client.get_instance_agent_command_execution(instance_agent_command_id=created.id,instance_id=instance).data
        state=str(getattr(execution,'lifecycle_state','')).upper()
        if state in {'SUCCEEDED','FAILED','TIMED_OUT','CANCELED'}:
            content=getattr(execution,'content',None)
            output=str(getattr(content,'text','') or '').strip()
            if state!='SUCCEEDED' or getattr(content,'exit_code',None)!=0 or not re.fullmatch(r'IDENTITY_ATLAS_QUARANTINE_RESTORE_OK backup_sha256=[a-f0-9]{64}',output):
                raise ReleaseError('Atlas restore rehearsal receipt missing')
            return output
        pause(3)
    raise ReleaseError('Atlas restore rehearsal timed out')


# Deployment code is installed by an independent trusted root SSH bootstrap,
# never by this OCI job or a GitHub merge. Admit only matching installed hashes.
ATLAS_RELEASE_SOURCES = {
    'host/identity-atlas-staging-deploy.py': ('/usr/local/sbin/shadowops-identity-atlas-deploy', '755'),
    'host/identity-atlas-staging-backup.py': ('/usr/local/sbin/shadowops-identity-atlas-backup', '755'),
    'scripts/identity_staging_atlas_transition.py': ('/usr/local/lib/shadowops/identity_staging_atlas_transition.py', '644'),
    'scripts/identity_staging_atlas_policy.py': ('/usr/local/lib/shadowops/identity_staging_atlas_policy.py', '644'),
    'scripts/shared_a1_host_guard.py': ('/usr/local/lib/shadowops/shared_a1_host_guard.py', '644'),
    **CANARY_SOURCES,
}


def atlas_release_host_command(digest, sha, hashes):
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ReleaseError('Invalid Atlas release identity')
    command = installed_source_guard(ATLAS_RELEASE_SOURCES, hashes)
    command += 'sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-deploy deploy ' + digest + ' ' + sha + '\n'
    return command


def execute_atlas_release(sdk, config, digest, sha, pause=time.sleep, clock=time.monotonic):
    command = atlas_release_host_command(digest, sha,
                canary_source_digests(sources=ATLAS_RELEASE_SOURCES))
    inspect(sdk, config)
    compartment, instance = resolve_existing_host(sdk, config)
    models = sdk.compute_instance_agent.models
    details = models.CreateInstanceAgentCommandDetails(
        compartment_id=compartment, execution_time_out_in_seconds=1000,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(
            source=models.InstanceAgentCommandSourceViaTextDetails(text=command),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')),
        display_name='identity-staging-atlas-release')
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    created = client.create_instance_agent_command(
        create_instance_agent_command_details=details).data
    if not getattr(created, 'id', None):
        raise ReleaseError('Missing Atlas release command reference')
    deadline = clock() + 1140
    while clock() < deadline:
        execution = client.get_instance_agent_command_execution(
            instance_agent_command_id=created.id, instance_id=instance).data
        state = str(getattr(execution, 'lifecycle_state', '')).upper()
        if state in {'SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELED'}:
            content = getattr(execution, 'content', None)
            expected = 'IDENTITY_ATLAS_DEPLOY_OK source_sha=' + sha + ' digest=' + digest
            if (state != 'SUCCEEDED' or getattr(content, 'exit_code', None) != 0
                    or str(getattr(content, 'text', '') or '').strip() != expected):
                raise ReleaseError('Atlas release missing exact runtime receipt; inspect private rollback checkpoint')
            return expected
        pause(3)
    raise ReleaseError('Atlas release timed out; check private rollback checkpoint')


def main():
    try:
        import oci
        config=config_from_env(oci,os.environ)
        if sys.argv[1:]==['atlas-release']:
            print(execute_atlas_release(oci,config,os.environ.get('ADMITTED_DIGEST',''),os.environ.get('ADMITTED_SHA','')))
        elif sys.argv[1:]==['atlas-restore-rehearsal']:
            print(execute_atlas_restore_rehearsal(oci,config))
        elif sys.argv[1:]==['atlas-backup']:
            print(execute_atlas_backup(oci,config))
        elif sys.argv[1:] in (['atlas-canary'], ['atlas-journey']):
            mode='journey' if sys.argv[1]=='atlas-journey' else 'canary'
            print(execute_atlas_canary(oci,config,os.environ.get('ADMITTED_DIGEST',''),os.environ.get('ADMITTED_SHA',''),mode=mode))
        elif sys.argv[1:]==['atlas-preflight']:
            print(execute_atlas_preflight(oci,config,os.environ.get('ADMITTED_DIGEST',''),os.environ.get('ADMITTED_SHA','')))
        elif sys.argv[1:]==['atlas-snooker-config']:
            print(execute_atlas_snooker_config(oci,config))
        elif sys.argv[1:]==['atlas-prepare']:
            print(execute_atlas_prepare(oci,config))
        elif sys.argv[1:]==['atlas-prepare-database-scoped']:
            print(execute_atlas_prepare(oci,config,mode='database-scoped'))
        elif sys.argv[1:]==['atlas-refresh-inventory']:
            print(execute_atlas_prepare(oci,config,mode='refresh-inventory'))
        elif sys.argv[1:]==['backup']:
            print(execute_backup(oci,config))
        elif sys.argv[1:]==['inspect']:
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
