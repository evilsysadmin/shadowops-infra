"""Narrow private CKA account bundle; independent from all lab/factory inputs."""
import base64
import json
import re

HOST = 'cka-api-staging.shadowops.dpdns.org'
ORIGIN = 'https://staging.cka.shadowops.dpdns.org'
SECRET = 'cka-account-staging-runtime'
PROJECT = 'shadowops-cka-account-staging'
IMAGE = 'ghcr.io/evilsysadmin/cka-account-staging@'
TUNNEL_IMAGE = 'cloudflare/cloudflared@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4'
SHA = re.compile(r'[a-f0-9]{40}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
VAULT = re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')

class AccountError(ValueError): pass

def public_keys(value):
    if not isinstance(value, dict) or set(value) != {'keys'} or not isinstance(value['keys'], list) or not 1 <= len(value['keys']) <= 3:
        raise AccountError('Invalid public key set')
    found = set()
    for key in value['keys']:
        if (not isinstance(key, dict) or set(key) != {'kty','crv','alg','use','kid','x'}
                or (key['kty'],key['crv'],key['alg'],key['use']) != ('OKP','Ed25519','EdDSA','sig')
                or not isinstance(key['kid'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key['kid']) or key['kid'] in found
                or not canonical32(key['x'])):
            raise AccountError('Invalid public signing key')
        found.add(key['kid'])

def canonical32(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value): return False
    raw = base64.urlsafe_b64decode(value + '=')
    return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value

def validate(bundle):
    if (not isinstance(bundle, dict) or set(bundle) != {'schema','environment','service_credential','jwks','identity_ca_pem','tunnel_token'}
            or type(bundle['schema']) is not int or bundle['schema'] != 1 or bundle['environment'] != 'staging'
            or not isinstance(bundle['service_credential'], str) or not bundle['service_credential'].startswith('soc1_')
            or not canonical32(bundle['service_credential'][5:])
            or not isinstance(bundle['tunnel_token'], str) or not re.fullmatch(r'[A-Za-z0-9_=-]{32,4096}', bundle['tunnel_token'])
            or len(json.dumps(bundle).encode()) > 24000):
        raise AccountError('Invalid isolated CKA account bundle')
    if not isinstance(bundle['identity_ca_pem'],str) or '-----BEGIN CERTIFICATE-----' not in bundle['identity_ca_pem'] or 'PRIVATE KEY' in bundle['identity_ca_pem']:
        raise AccountError('Public Identity TLS CA required')
    public_keys(bundle['jwks'])

def account_config(bundle, sha):
    validate(bundle)
    if not isinstance(sha, str) or not SHA.fullmatch(sha): raise AccountError('Invalid account source')
    return {'environment':'staging','service_credential':bundle['service_credential'],'jwks':bundle['jwks'],'identity_ca_pem':bundle['identity_ca_pem'],'build':sha}
