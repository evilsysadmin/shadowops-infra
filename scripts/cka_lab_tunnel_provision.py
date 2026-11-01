"""Manual Infra-only Cloudflare/Vault preparation; no controller or browser activation."""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse

from chronicles_api_provision import Cloudflare, ProvisionError, resolve_vault
from oci_control_plane import config_from_env, resolve_existing_host, verified_run_command_host
from cka_lab_private_api import ApiError, HOST, decode, release
from cka_lab_tunnel import NAME, SECRET, ZONE, LOCATOR, TAGS, UUID, bundle, locator


def rows(sdk, call, *args, **kwargs):
    result = sdk.pagination.list_call_get_all_results(call, *args, **kwargs).data
    if not isinstance(result, list):
        raise ProvisionError('Complete inventory required')
    return result


def free_secret_inventory(sdk, config):
    identity = sdk.identity.IdentityClient(config)
    regions = rows(sdk, identity.list_region_subscriptions, config['tenancy'])
    home = [r for r in regions if getattr(r, 'is_home_region', None) is True]
    if len(home) != 1 or home[0].region_name != config['region']:
        raise ProvisionError('Existing home-region Vault required')
    compartments = rows(sdk, identity.list_compartments, config['tenancy'], access_level='ANY', compartment_id_in_subtree=True)
    ids = [config['tenancy']]
    for item in compartments:
        state = getattr(item, 'lifecycle_state', None)
        if not isinstance(state, str) or not state:
            raise ProvisionError('Unknown compartment state')
        if state != 'DELETED':
            if not isinstance(getattr(item, 'id', None), str) or item.id in ids:
                raise ProvisionError('Ambiguous compartment inventory')
            ids.append(item.id)
    secrets, names = set(), set()
    for region in regions:
        name = getattr(region, 'region_name', None)
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z0-9-]{3,64}', name)
                or name in names or getattr(region, 'status', None) != 'READY'):
            raise ProvisionError('Complete subscribed-region inventory required')
        names.add(name)
        client = sdk.vault.VaultsClient({**config, 'region': name})
        for compartment in ids:
            for item in rows(sdk, client.list_secrets, compartment):
                state = getattr(item, 'lifecycle_state', None)
                if not isinstance(state, str) or not state:
                    raise ProvisionError('Unknown secret state')
                if state != 'DELETED':
                    identity = getattr(item, 'id', None)
                    if not isinstance(identity, str) or identity in secrets:
                        raise ProvisionError('Ambiguous secret inventory')
                    secrets.add(identity)
                    if len(secrets) > 150:
                        raise ProvisionError('Always Free secret envelope exceeded')
    return secrets


def tunnels(cf):
    result = []
    for page in range(1, 12):
        values = cf.call('GET', f'/accounts/{cf.account}/cfd_tunnel?' + urllib.parse.urlencode(
            {'is_deleted': 'false', 'per_page': 100, 'page': page}))
        if not isinstance(values, list):
            raise ProvisionError('Complete tunnel inventory required')
        result.extend(values)
        if len(result) > 1000:
            raise ProvisionError('No-cost tunnel envelope exceeded')
        if len(values) < 100:
            return result
    raise ProvisionError('Incomplete tunnel inventory')


def desired_ingress():
    return {'config': {'ingress': [
        {'hostname': HOST, 'service': 'http://cka-lab:8080',
         'originRequest': {'httpHostHeader': HOST, 'connectTimeout': 10}},
        {'service': 'http_status:404'}]}}


def provision(sdk, env, cf, pin):
    release(pin)
    if not re.fullmatch(r'[a-f0-9]{32}', cf.account):
        raise ProvisionError('Fixed Cloudflare account required')
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    # Resolver only reads an already-existing ACTIVE Vault and ENABLED key.
    vault, key, _ = resolve_vault(sdk, config, compartment)
    metadata = sdk.key_management.KmsVaultClient(config).get_vault(vault).data
    if getattr(metadata, 'vault_type', None) != 'DEFAULT':
        raise ProvisionError('Existing default Vault required; no paid Vault creation')
    inventory = free_secret_inventory(sdk, config)
    client = sdk.vault.VaultsClient(config)
    current = rows(sdk, client.list_secrets, compartment, vault_id=vault, name=SECRET)
    if len(current) > 1:
        raise ProvisionError('Ambiguous lab tunnel custody')
    if current:
        item = current[0]
        info = client.get_secret(item.id).data
        if (item.id not in inventory or str(item.lifecycle_state) != 'ACTIVE'
                or getattr(info, 'key_id', None) != key or getattr(info, 'vault_id', None) != vault
                or getattr(info, 'freeform_tags', {}) != TAGS):
            raise ProvisionError('Existing lab tunnel custody requires review')
    elif len(inventory) >= 150:
        raise ProvisionError('No Always Free secret slot available')
    all_tunnels = tunnels(cf)
    matches = [t for t in all_tunnels if t.get('name') == NAME]
    if len(matches) > 1:
        raise ProvisionError('Ambiguous lab tunnel')
    tunnel = matches[0] if matches else None
    if tunnel and (tunnel.get('config_src') != 'cloudflare' or not UUID.fullmatch(str(tunnel.get('id', '')))):
        raise ProvisionError('Lab tunnel ownership mismatch')
    if tunnel is None and len(all_tunnels) >= 1000:
        raise ProvisionError('No no-cost tunnel slot available')
    zones = cf.call('GET', '/zones?' + urllib.parse.urlencode({'name': ZONE, 'account.id': cf.account}))
    if not isinstance(zones, list) or len(zones) != 1 or zones[0].get('name') != ZONE:
        raise ProvisionError('Unambiguous owned DNS zone required')
    zone = zones[0]['id']
    dns = cf.call('GET', f'/zones/{zone}/dns_records?' + urllib.parse.urlencode({'name': HOST}))
    target = tunnel['id'] + '.cfargotunnel.com' if tunnel else None
    if (not isinstance(dns, list) or len(dns) > 1
            or (dns and (dns[0].get('name') != HOST or dns[0].get('type') != 'CNAME'
                         or dns[0].get('content') != target or dns[0].get('proxied') is not True))):
        raise ProvisionError('Lab hostname belongs to another owner')
    if tunnel:
        existing = cf.call('GET', f'/accounts/{cf.account}/cfd_tunnel/{tunnel["id"]}/configurations')
        ingress = (existing or {}).get('config', {}).get('ingress', [])
        if ingress not in ([], [{'service': 'http_status:404'}], desired_ingress()['config']['ingress']):
            raise ProvisionError('Existing tunnel ingress belongs to another owner')
    old = None
    if current:
        if tunnel is None:
            raise ProvisionError('Preserve existing custody after a deleted tunnel')
        encoded = sdk.secrets.SecretsClient(config).get_secret_bundle_by_name(secret_name=SECRET, vault_id=vault, stage='CURRENT').data.secret_bundle_content.content
        old = bundle(decode(base64.b64decode(encoded, validate=True)))
        if old['tunnel_id'] != tunnel['id'] or old['account_id'] != cf.account:
            raise ProvisionError('Lab tunnel secret is bound to another owner')
    print('CKA_LAB_FREE_PUBLICATION_CAPACITY ' + json.dumps({
        'vault_secrets_before': len(inventory), 'vault_secrets_projected': len(inventory) + int(not current),
        'vault_secret_limit': 150, 'tunnels_before': len(all_tunnels),
        'tunnels_projected': len(all_tunnels) + int(tunnel is None), 'tunnel_limit': 1000,
        'new_vaults': 0, 'new_master_keys': 0, 'new_compute': 0}, sort_keys=True), flush=True)
    # All capacity/custody/ownership preflights finish before the first mutation.
    if tunnel is None:
        tunnel = cf.call('POST', f'/accounts/{cf.account}/cfd_tunnel', {'name': NAME, 'config_src': 'cloudflare'})
        if tunnel.get('config_src') != 'cloudflare' or not UUID.fullmatch(str(tunnel.get('id', ''))):
            raise ProvisionError('Invalid created lab tunnel')
        target = tunnel['id'] + '.cfargotunnel.com'
    token = cf.call('GET', f'/accounts/{cf.account}/cfd_tunnel/{tunnel["id"]}/token')
    payload = bundle({'schema': 1, 'environment': 'staging', 'hostname': HOST, 'account_id': cf.account,
        'tunnel_id': tunnel['id'], 'tunnel_token': token, 'source_sha': pin['source_sha'], 'image_digest': pin['image_digest']}, pin)
    same = old == payload
    if not same:
        content = sdk.vault.models.Base64SecretContentDetails(content_type='BASE64', stage='CURRENT',
            content=base64.b64encode(json.dumps(payload).encode()).decode())
        operations = sdk.vault.VaultsClientCompositeOperations(client)
        wait = {'wait_for_states': ['ACTIVE'], 'waiter_kwargs': {'max_interval_seconds': 5, 'max_wait_seconds': 300}}
        if current:
            operations.update_secret_and_wait_for_state(current[0].id, sdk.vault.models.UpdateSecretDetails(secret_content=content), **wait)
        else:
            operations.create_secret_and_wait_for_state(sdk.vault.models.CreateSecretDetails(compartment_id=compartment,
                vault_id=vault, key_id=key, secret_name=SECRET, freeform_tags=TAGS,
                description='CKA staging tunnel only; no Identity or user credentials', secret_content=content), **wait)
    cf.call('PUT', f'/accounts/{cf.account}/cfd_tunnel/{tunnel["id"]}/configurations', desired_ingress())
    if not dns:
        cf.call('POST', f'/zones/{zone}/dns_records', {'name': HOST, 'type': 'CNAME', 'content': target,
            'proxied': True, 'comment': 'Dedicated authenticated CKA staging labs; shadowops-infra'})
    return locator({'schema': 1, 'environment': 'staging', 'hostname': HOST, 'vault_id': vault,
        'tunnel_id': tunnel['id'], 'source_sha': pin['source_sha'], 'image_digest': pin['image_digest'],
        'created_at': datetime.now(timezone.utc).isoformat()})


def locator_command(value):
    locator(value)
    # Only public release/location metadata enters Run Command, never the token.
    return "set -eu\npython3 -I - <<'CKA_LOCATOR'\n" + '''import json,os,stat,tempfile
from pathlib import Path
destination=Path(''' + repr(LOCATOR) + ''')
value=json.loads(''' + repr(json.dumps(value)) + ''')
if destination.exists() or destination.is_symlink():
 info=destination.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise SystemExit(1)
fd,name=tempfile.mkstemp(prefix='.cka-lab-locator-',dir='/tmp')
try:
 os.fchmod(fd,0o600)
 with os.fdopen(fd,'w') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
 os.replace(name,destination)
finally:Path(name).unlink(missing_ok=True)
print('CKA_LAB_TUNNEL_LOCATOR_STAGED')
CKA_LOCATOR
'''


def stage_locator(sdk, config, value):
    compartment, instance = verified_run_command_host(sdk, config)
    models = sdk.compute_instance_agent.models
    details = models.CreateInstanceAgentCommandDetails(compartment_id=compartment, execution_time_out_in_seconds=90,
        target=models.InstanceAgentCommandTarget(instance_id=instance),
        content=models.InstanceAgentCommandContent(source=models.InstanceAgentCommandSourceViaTextDetails(text=locator_command(value)),
            output=models.InstanceAgentCommandOutputViaTextDetails(output_type='TEXT')), display_name='cka-lab-nonsecret-tunnel-locator')
    client = sdk.compute_instance_agent.ComputeInstanceAgentClient(config)
    request = client.create_instance_agent_command(create_instance_agent_command_details=details).data
    if not isinstance(getattr(request, 'id', None), str) or not request.id:
        raise ProvisionError('Missing nonsecret locator request reference')
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        result = client.get_instance_agent_command_execution(instance_agent_command_id=request.id, instance_id=instance).data
        if result.lifecycle_state in {'SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELED'}:
            content = result.content
            if result.lifecycle_state != 'SUCCEEDED' or content.exit_code != 0 or content.text.strip() != 'CKA_LAB_TUNNEL_LOCATOR_STAGED':
                raise ProvisionError('Nonsecret locator staging did not verify')
            return
        time.sleep(2)
    raise ProvisionError('Nonsecret locator staging timed out')


def main():
    try:
        if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or os.environ.get('GITHUB_REF') != 'refs/heads/main'
                or os.environ.get('GITHUB_REPOSITORY') != 'evilsysadmin/shadowops-infra'):
            raise ProvisionError('Manual protected Infra main workflow required')
        import oci
        pin = release(decode(Path('deploy/cka-lab-staging-release.json').read_bytes()))
        value = provision(oci, os.environ, Cloudflare(os.environ), pin)
        stage_locator(oci, config_from_env(oci, os.environ), value)
        print('CKA_LAB_TUNNEL_PREPARED free_capacity_checked=true locator_staged=true')
        return 0
    except (ProvisionError, ApiError) as error:
        print('CKA_LAB_TUNNEL_PROVISION_BLOCKED: ' + str(error), file=sys.stderr)
        return 1
    except Exception:
        print('CKA_LAB_TUNNEL_PROVISION_BLOCKED: no verified preparation', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
