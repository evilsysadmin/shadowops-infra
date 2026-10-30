#!/usr/bin/env python3
"""Provision only the isolated Identity staging tunnel, DNS and operator Vault secret."""
from __future__ import annotations

import base64
import json
import os
import urllib.parse

from chronicles_api_provision import Cloudflare, ProvisionError, UUID_RE, resolve_vault
from identity_staging_bundle import HOST, BundleError, generate, validate
from oci_control_plane import config_from_env, resolve_existing_host

TUNNEL_NAME = 'identity-staging'
SECRET_NAME = 'identity-staging-operator-bundle'
ZONE = 'shadowops.dpdns.org'


def desired_ingress() -> dict:
    # caPool and originServerName authenticate our private TLS origin.
    # https://developers.cloudflare.com/tunnel/reference/origin-parameters/
    return {'config': {'ingress': [
        {'hostname': HOST, 'service': 'https://identity:9443', 'originRequest': {
            'httpHostHeader': HOST, 'originServerName': HOST,
            'caPool': '/run/identity/ca.pem', 'noTLSVerify': False, 'connectTimeout': 10}},
        {'service': 'http_status:404'},
    ]}}


def ensure_tunnel(cf):
    rows = cf.call('GET', f'/accounts/{cf.account}/cfd_tunnel?' +
                   urllib.parse.urlencode({'name': TUNNEL_NAME, 'is_deleted': 'false'}))
    rows = [r for r in rows or [] if r.get('name') == TUNNEL_NAME]
    if len(rows) > 1:
        raise ProvisionError('Duplicate Identity staging tunnels')
    tunnel = rows[0] if rows else cf.call('POST', f'/accounts/{cf.account}/cfd_tunnel',
                                         {'name': TUNNEL_NAME, 'config_src': 'cloudflare'})
    if tunnel.get('config_src') != 'cloudflare' or not UUID_RE.fullmatch(tunnel.get('id', '')):
        raise ProvisionError('Identity tunnel ownership mismatch')
    return tunnel['id']


def dns_plan(cf, tunnel_id):
    zones = cf.call('GET', '/zones?' + urllib.parse.urlencode({'name': ZONE, 'account.id': cf.account}))
    if not isinstance(zones, list) or len(zones) != 1:
        raise ProvisionError('Expected one ShadowOps zone')
    zone = zones[0]['id']
    rows = cf.call('GET', f'/zones/{zone}/dns_records?' + urllib.parse.urlencode({'name': HOST})) or []
    target = tunnel_id + '.cfargotunnel.com'
    if len(rows) > 1 or (rows and (rows[0].get('type') != 'CNAME' or rows[0].get('content') != target or rows[0].get('proxied') is not True)):
        raise ProvisionError('Identity hostname belongs to another target')
    return zone, target, bool(rows)


def load_existing(sdk, config, vault_id, compartment):
    metadata = sdk.pagination.list_call_get_all_results(
        sdk.vault.VaultsClient(config).list_secrets, compartment,
        vault_id=vault_id, name=SECRET_NAME).data
    # An inaccessible/pending/deleted secret is not permission to replace keys.
    if not metadata:
        return None
    if len(metadata) != 1 or str(metadata[0].lifecycle_state).upper() != 'ACTIVE':
        raise ProvisionError('Identity custody requires operator review')
    try:
        bundle = sdk.secrets.SecretsClient(config).get_secret_bundle_by_name(
            secret_name=SECRET_NAME, vault_id=vault_id, stage='CURRENT').data
    except sdk.exceptions.ServiceError as exc:
        raise ProvisionError('Identity Vault read failed') from None
    try:
        raw = base64.b64decode(bundle.secret_bundle_content.content, validate=True)
        if len(raw) > 24000:
            raise BundleError('oversize')
        value = json.loads(raw)
        validate(value)
        return value
    except (ValueError, TypeError, KeyError):
        raise ProvisionError('Existing Identity bundle is invalid; no regeneration allowed') from None


def store(sdk, config, compartment, vault, key, bundle):
    validate(bundle)
    client = sdk.vault.VaultsClient(config)
    operations = sdk.vault.VaultsClientCompositeOperations(client)
    rows = sdk.pagination.list_call_get_all_results(client.list_secrets, compartment,
                                                   vault_id=vault, name=SECRET_NAME).data
    rows = [r for r in rows if str(r.lifecycle_state).upper() == 'ACTIVE']
    if len(rows) > 1:
        raise ProvisionError('Duplicate Identity operator secrets')
    content = sdk.vault.models.Base64SecretContentDetails(content_type='BASE64', stage='CURRENT',
        content=base64.b64encode(json.dumps(bundle).encode()).decode())
    wait = {'wait_for_states': ['ACTIVE'], 'waiter_kwargs': {'max_interval_seconds': 5, 'max_wait_seconds': 300}}
    if rows:
        operations.update_secret_and_wait_for_state(rows[0].id,
            sdk.vault.models.UpdateSecretDetails(secret_content=content), **wait)
    else:
        operations.create_secret_and_wait_for_state(sdk.vault.models.CreateSecretDetails(
            compartment_id=compartment, vault_id=vault, key_id=key, secret_name=SECRET_NAME,
            description='Independent Identity staging operator custody; never mount the full bundle in a service',
            freeform_tags={'application': 'shadowops-identity', 'environment': 'staging', 'managed-by': 'shadowops-infra'},
            secret_content=content), **wait)


def provision(sdk, env, cf):
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    vault, key, _ = resolve_vault(sdk, config, compartment)
    existing = load_existing(sdk, config, vault, compartment)  # fail before mutation on invalid custody
    tunnel = ensure_tunnel(cf)
    zone, target, dns_exists = dns_plan(cf, tunnel)
    token = cf.call('GET', f'/accounts/{cf.account}/cfd_tunnel/{tunnel}/token')
    old_token = existing['tunnel_token'] if existing else None
    bundle = dict(existing) if existing else generate(token)
    bundle['tunnel_token'] = token
    validate(bundle)
    if existing is None or token != old_token:
        store(sdk, config, compartment, vault, key, bundle)
    cf.call('PUT', f'/accounts/{cf.account}/cfd_tunnel/{tunnel}/configurations', desired_ingress())
    if not dns_exists:
        cf.call('POST', f'/zones/{zone}/dns_records', {'type': 'CNAME', 'name': HOST, 'content': target,
            'proxied': True, 'comment': 'Isolated Identity staging, managed by shadowops-infra'})
    return 'IDENTITY_STAGING_PROVISIONED custody=preserved' if existing else 'IDENTITY_STAGING_PROVISIONED custody=created'


def main():
    try:
        import oci
        print(provision(oci, os.environ, Cloudflare(os.environ)))
    except Exception as exc:
        # SDK and TLS diagnostics may contain credentials or identifiers.
        print('IDENTITY_STAGING_PROVISION_BLOCKED type=' + type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
