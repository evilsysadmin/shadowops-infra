#!/usr/bin/env python3
"""Rotate only the inventory password in the independent staging Atlas secret."""
import base64
import json
import os
import time

from chronicles_api_provision import resolve_vault
from identity_staging_atlas_custody import AtlasCustodyError, rotate_inventory_uri
from identity_staging_atlas_provision import SECRET, MAX_SIZE, existing_secret, validate_inputs
from identity_staging_release import execute_atlas_prepare
from oci_control_plane import config_from_env, resolve_existing_host


def rotate(sdk, env, pause=time.sleep):
    uris = validate_inputs(*(env.get('IDENTITY_ATLAS_STAGING_' + name + '_URI', '')
                             for name in ('RUNTIME', 'INVENTORY', 'BACKUP')))
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    vault, _, _ = resolve_vault(sdk, config, compartment)
    client = sdk.vault.VaultsClient(config)
    entries = sdk.pagination.list_call_get_all_results(client.list_secrets, compartment,
                      vault_id=vault, name=SECRET).data
    if len(entries) != 1 or str(entries[0].lifecycle_state).upper() != 'ACTIVE':
        raise AtlasCustodyError('Dedicated Atlas custody unavailable')
    secret_id = str(entries[0].id)
    if not secret_id:
        raise AtlasCustodyError('Dedicated Atlas custody unavailable')
    metadata = client.get_secret(secret_id)
    etag = metadata.headers.get('etag')
    if not etag or str(metadata.data.lifecycle_state).upper() != 'ACTIVE':
        raise AtlasCustodyError('Dedicated Atlas custody unavailable')
    original = existing_secret(sdk, config, vault, compartment)
    updated = rotate_inventory_uri(original, *uris)
    if updated == original:
        return 'IDENTITY_ATLAS_INVENTORY_CUSTODY_UNCHANGED'
    # Never rotate the candidate's custody while any running container has
    # mounted it. The installed staging-only guard must return a positive receipt.
    execute_atlas_prepare(sdk, config, mode='check-inventory-inactive')
    raw = json.dumps(updated, separators=(',', ':')).encode()
    if len(raw) > MAX_SIZE:
        raise AtlasCustodyError('Invalid Atlas custody')
    content = sdk.vault.models.Base64SecretContentDetails(content_type='BASE64', stage='CURRENT',
              content=base64.b64encode(raw).decode())
    request = sdk.vault.models.UpdateSecretDetails(secret_content=content)
    client.update_secret(secret_id, request, if_match=etag)
    for _ in range(30):
        try:
            if existing_secret(sdk, config, vault, compartment) == updated:
                return 'IDENTITY_ATLAS_INVENTORY_CUSTODY_ROTATED'
        except AtlasCustodyError:
            pass
        pause(2)
    raise AtlasCustodyError('Atlas custody update unconfirmed')


def main():
    try:
        import oci
        print(rotate(oci, os.environ))
        return 0
    except Exception as exc:
        # SDK exceptions may contain the supplied secrets; never print them.
        print('IDENTITY_ATLAS_INVENTORY_ROTATE_BLOCKED type=' + type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
