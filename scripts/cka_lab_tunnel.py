"""Narrow lab-only encrypted tunnel bundle and nonsecret operator locator."""
import re
from datetime import datetime, timezone
from cka_lab_private_api import ApiError, HOST, release

NAME = 'cka-lab-staging'
SECRET = 'cka-lab-staging-tunnel'
ZONE = 'shadowops.dpdns.org'
LOCATOR = '/tmp/shadowops-cka-lab-tunnel-locator.json'
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
VAULT = re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')
TOKEN = re.compile(r'[A-Za-z0-9_+/=-]{32,4096}')
TAGS = {'application': NAME, 'environment': 'staging', 'managed-by': 'shadowops-infra'}
CF_IMAGE = 'cloudflare/cloudflared@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4'
CF_COMMAND = ['tunnel', '--no-autoupdate', '--metrics', '127.0.0.1:20243', 'run']


def bundle(value, pin=None):
    fields = {'schema', 'environment', 'hostname', 'account_id', 'tunnel_id', 'tunnel_token', 'source_sha', 'image_digest'}
    if (type(value) is not dict or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or value['environment'] != 'staging' or value['hostname'] != HOST
            or type(value['account_id']) is not str or not re.fullmatch(r'[a-f0-9]{32}', value['account_id'])
            or type(value['tunnel_id']) is not str or not UUID.fullmatch(value['tunnel_id'])
            or type(value['tunnel_token']) is not str or not TOKEN.fullmatch(value['tunnel_token'])):
        raise ApiError('Invalid isolated lab tunnel bundle')
    actual = release({key: value[key] for key in ('schema', 'source_sha', 'image_digest')})
    if pin is not None and actual != pin:
        raise ApiError('Tunnel release differs from the reviewed controller')
    return value


def locator(value, pin=None, *, now=None):
    fields = {'schema', 'environment', 'hostname', 'vault_id', 'tunnel_id', 'source_sha', 'image_digest', 'created_at'}
    if (type(value) is not dict or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or value['environment'] != 'staging' or value['hostname'] != HOST
            or type(value['vault_id']) is not str or not VAULT.fullmatch(value['vault_id'])
            or type(value['tunnel_id']) is not str or not UUID.fullmatch(value['tunnel_id'])
            or type(value['created_at']) is not str):
        raise ApiError('Invalid nonsecret lab locator')
    actual = release({key: value[key] for key in ('schema', 'source_sha', 'image_digest')})
    if pin is not None and actual != pin:
        raise ApiError('Locator source mismatch')
    created = datetime.fromisoformat(value['created_at'].replace('Z', '+00:00'))
    if created.tzinfo is None or not -30 <= ((now or datetime.now(timezone.utc)) - created).total_seconds() <= 7200:
        raise ApiError('Fresh lab locator required')
    return value
