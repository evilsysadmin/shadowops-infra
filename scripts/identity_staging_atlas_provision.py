#!/usr/bin/env python3
"""Provision only the independent Atlas staging custody secret. No deployment."""
import base64
import json
import os

from chronicles_api_provision import resolve_vault
from identity_staging_atlas_custody import AtlasCustodyError, prepare_atlas_custody
from identity_staging_atlas import AtlasConfigurationError, _connection, normalize_atlas_uri
from oci_control_plane import config_from_env, resolve_existing_host

SECRET = 'identity-staging-atlas-custody'
MAX_SIZE = 24000


def existing_secret(sdk, config, vault_id, compartment):
    rows = sdk.pagination.list_call_get_all_results(
        sdk.vault.VaultsClient(config).list_secrets, compartment,
        vault_id=vault_id, name=SECRET).data
    if not rows:
        return None
    if len(rows) != 1 or str(rows[0].lifecycle_state).upper() != 'ACTIVE':
        raise AtlasCustodyError('Atlas custody is unavailable')
    try:
        data = sdk.secrets.SecretsClient(config).get_secret_bundle_by_name(
            secret_name=SECRET, vault_id=vault_id, stage='CURRENT').data
        raw = base64.b64decode(data.secret_bundle_content.content, validate=True)
        if len(raw) > MAX_SIZE:
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except Exception:
        raise AtlasCustodyError('Atlas custody is unavailable') from None


def store_new(sdk, config, compartment, vault, key, value):
    content = json.dumps(value, separators=(',', ':')).encode()
    if len(content) > MAX_SIZE:
        raise AtlasCustodyError('Atlas custody is invalid')
    # Create only: never update or overwrite existing credentials or keys.
    client = sdk.vault.VaultsClient(config)
    operations = sdk.vault.VaultsClientCompositeOperations(client)
    body = sdk.vault.models.Base64SecretContentDetails(content_type='BASE64', stage='CURRENT',
                content=base64.b64encode(content).decode())
    request = sdk.vault.models.CreateSecretDetails(
        compartment_id=compartment, vault_id=vault, key_id=key, secret_name=SECRET,
        description='Independent Identity staging Atlas custody',
        freeform_tags={'application':'shadowops-identity','environment':'staging','managed-by':'shadowops-infra'},
        secret_content=body)
    operations.create_secret_and_wait_for_state(request, wait_for_states=['ACTIVE'],
        waiter_kwargs={'max_interval_seconds':5,'max_wait_seconds':300})


class AtlasInputError(AtlasCustodyError):
    def __init__(self, code):
        super().__init__('Atlas input validation failed')
        self.code = code


def validate_inputs(app, inventory, backup):
    """Return only fixed diagnostic categories, never URI or user content."""
    parsed = []
    normalized = []
    problems = []
    for name, uri in (('runtime', app), ('inventory', inventory), ('backup', backup)):
        try:
            normalized_uri = normalize_atlas_uri(uri)
            parsed.append(_connection(normalized_uri))
            normalized.append(normalized_uri)
        except AtlasConfigurationError:
            problems.append(name + '_uri_format')
    if problems:
        raise AtlasInputError(','.join(problems)) from None
    if len({host for host, _ in parsed}) != 1:
        raise AtlasInputError('cluster_mismatch')
    if len({user for _, user in parsed}) != 3:
        raise AtlasInputError('users_not_distinct')
    try:
        prepare_atlas_custody(None, *normalized)
    except AtlasCustodyError:
        raise AtlasInputError('backup_credential_format') from None
    return tuple(normalized)


def provision(sdk, env):
    app = env.get('IDENTITY_ATLAS_STAGING_RUNTIME_URI', '')
    inventory = env.get('IDENTITY_ATLAS_STAGING_INVENTORY_URI', '')
    backup = env.get('IDENTITY_ATLAS_STAGING_BACKUP_URI', '')
    # Validate user-supplied config before accessing any cloud resource.
    app, inventory, backup = validate_inputs(app, inventory, backup)
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    vault, key, _ = resolve_vault(sdk, config, compartment)
    existing = existing_secret(sdk, config, vault, compartment)
    custody = prepare_atlas_custody(existing, app, inventory, backup)
    if existing is None:
        store_new(sdk, config, compartment, vault, key, custody)
        return 'IDENTITY_ATLAS_CUSTODY_CREATED'
    return 'IDENTITY_ATLAS_CUSTODY_PRESERVED'


def main():
    try:
        import oci
        print(provision(oci, os.environ))
        return 0
    except AtlasInputError as exc:
        print('IDENTITY_ATLAS_CUSTODY_INPUT_INVALID reason=' + exc.code)
        return 1
    except Exception as exc:
        # Never print SDK messages: they may contain supplied URIs or credentials.
        print('IDENTITY_ATLAS_CUSTODY_BLOCKED type=' + type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
