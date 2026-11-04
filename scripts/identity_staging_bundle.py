#!/usr/bin/env python3
"""Private staging-only operator bundle. Never print its contents or pass via argv."""
from __future__ import annotations

import base64
import json
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

HOST = 'id-staging.shadowops.dpdns.org'
DATABASE = 'shadowops_identity_staging'
SCHEMA = 1
KEYS = frozenset({'schema', 'environment', 'ca_certificate_pem', 'ca_private_key_pem',
                  'mongo_certificate_key_pem', 'mongo_replica_key', 'mongo_root_password',
                  'mongo_application_password', 'signing_seed', 'tls_certificate_pem',
                  'tls_private_key_pem', 'consumers', 'backup_key', 'tunnel_token'})


class BundleError(ValueError):
    pass


def random32() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')


def generate(tunnel_token: str) -> dict:
    """Generate once, then keep in independent OCI Vault custody; never regenerate on retry."""
    with tempfile.TemporaryDirectory(prefix='identity-staging-certificates-') as temp:
        directory = Path(temp)
        def openssl(*args):
            try:
                subprocess.run(['openssl', *args], cwd=directory, check=True,
                               capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                raise BundleError('Certificate generation failed') from None
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '365',
                '-subj', '/CN=ShadowOps Identity staging private CA',
                '-keyout', 'ca.key', '-out', 'ca.pem')
        for name, subject, san in [('mongo', 'identity-mongo', 'DNS:identity-mongo,DNS:localhost,IP:127.0.0.1'),
                                    ('identity', HOST, 'DNS:' + HOST)]:
            openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                    '-subj', '/CN=' + subject, '-keyout', name + '.key', '-out', name + '.csr')
            (directory / (name + '.ext')).write_text(
                'subjectAltName=' + san + '\nextendedKeyUsage=serverAuth,clientAuth\n'
                'keyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n')
            openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                    '-CAcreateserial', '-days', '90', '-sha256', '-extfile', name + '.ext',
                    '-out', name + '.crt')
        read = lambda name: (directory / name).read_text()
        bundle = {
            'schema': SCHEMA, 'environment': 'staging',
            'ca_certificate_pem': read('ca.pem'), 'ca_private_key_pem': read('ca.key'),
            'mongo_certificate_key_pem': read('mongo.key') + read('mongo.crt'),
            'mongo_replica_key': base64.b64encode(secrets.token_bytes(512)).decode(),
            'mongo_root_password': secrets.token_hex(32),
            'mongo_application_password': secrets.token_hex(32),
            'signing_seed': random32(),
            'tls_certificate_pem': read('identity.crt') + read('ca.pem'),
            'tls_private_key_pem': read('identity.key'),
            'consumers': {'chronicles': 'soc1_' + random32()},
            'backup_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            'tunnel_token': tunnel_token,
        }
        validate(bundle)
        return bundle


def validate(bundle: dict) -> None:
    if not isinstance(bundle, dict) or set(bundle) not in (KEYS, KEYS | {'admin_inventory'}) or type(bundle['schema']) is not int or bundle['schema'] != SCHEMA or bundle['environment'] != 'staging':
        raise BundleError('Invalid staging operator schema')
    for key in KEYS - {'schema', 'consumers'}:
        if not isinstance(bundle[key], str) or not bundle[key] or '\x00' in bundle[key]:
            raise BundleError('Invalid operator field')
    if len(json.dumps(bundle).encode()) > 24000:
        raise BundleError('Operator bundle exceeds Vault limit')
    for key in ('mongo_root_password', 'mongo_application_password'):
        if not re.fullmatch('[a-f0-9]{64}', bundle[key]):
            raise BundleError('Invalid isolated database credential')
    if bundle['mongo_root_password'] == bundle['mongo_application_password']:
        raise BundleError('Independent database credentials required')
    if 'admin_inventory' in bundle:
        admin=bundle['admin_inventory']
        if not isinstance(admin,dict) or set(admin)!={'mongo_password','access_history'} or admin['access_history'] is not True or not isinstance(admin['mongo_password'],str) or not re.fullmatch('[a-f0-9]{64}',admin['mongo_password']) or admin['mongo_password'] in {bundle['mongo_root_password'],bundle['mongo_application_password']}:
            raise BundleError('Independent administrative database credential required')
    if not re.fullmatch('[A-Za-z0-9_-]{43}', bundle['signing_seed']):
        raise BundleError('Invalid independent signing seed')
    consumers = bundle['consumers']
    if (not isinstance(consumers, dict) or 'chronicles' not in consumers
            or not set(consumers) <= {'chronicles', 'cka-simulator', 'football', 'pawn-action'}
            or any(not isinstance(v, str) or not re.fullmatch('soc1_[A-Za-z0-9_-]{43}', v) for v in consumers.values())
            or len(set(consumers.values())) != len(consumers)
            or any(v[5:] in {bundle['signing_seed'], bundle['backup_key'].rstrip('=')} for v in consumers.values())):
        raise BundleError('Explicit independent staging consumer credentials required')
    for key, label in [('ca_certificate_pem', 'CERTIFICATE'), ('tls_certificate_pem', 'CERTIFICATE'),
                       ('ca_private_key_pem', 'PRIVATE KEY'), ('tls_private_key_pem', 'PRIVATE KEY')]:
        if '-----BEGIN ' + label + '-----' not in bundle[key]:
            raise BundleError('Invalid certificate material')
    if 'PRIVATE KEY' not in bundle['mongo_certificate_key_pem'] or 'CERTIFICATE' not in bundle['mongo_certificate_key_pem']:
        raise BundleError('Invalid database TLS material')
    if not re.fullmatch('[A-Za-z0-9+/=]{684}', bundle['mongo_replica_key']):
        raise BundleError('Invalid replica key')
    if not re.fullmatch('[A-Za-z0-9_-]{43}=', bundle['backup_key']):
        raise BundleError('Invalid backup encryption key')
    if not re.fullmatch('[A-Za-z0-9_=-]{32,4096}', bundle['tunnel_token']):
        raise BundleError('Invalid tunnel credential')


def service_config(bundle: dict) -> dict:
    validate(bundle)
    result = {
        'environment': 'staging',
        'mongo_uri': 'mongodb://identity_runtime:' + bundle['mongo_application_password'] +
            '@identity-mongo:27017/' + DATABASE +
            '?replicaSet=identity-staging-rs&tls=true&authSource=' + DATABASE,
        'mongo_ca_pem': bundle['ca_certificate_pem'], 'signing_seed': bundle['signing_seed'],
        'tls_certificate_pem': bundle['tls_certificate_pem'],
        'tls_private_key_pem': bundle['tls_private_key_pem'], 'consumers': bundle['consumers'],
    }
    if 'admin_inventory' in bundle:
        result['admin_inventory_mongo_uri'] = 'mongodb://identity_inventory:' + bundle['admin_inventory']['mongo_password'] + '@identity-mongo:27017/' + DATABASE + '?replicaSet=identity-staging-rs&tls=true&authSource=' + DATABASE
        result['admin_inventory_access_history'] = True
    return result


def enable_admin_inventory(bundle: dict) -> dict:
    """Add independent staging inventory custody once; preserve all existing material."""
    validate(bundle)
    result=dict(bundle)
    if 'admin_inventory' not in result:
        result['admin_inventory']={'mongo_password':secrets.token_hex(32),'access_history':True}
    validate(result)
    return result


def enable_cka(bundle: dict) -> dict:
    """Explicit, idempotent opt-in. Preserve every existing key/account/consumer."""
    validate(bundle)
    result = dict(bundle)
    result['consumers'] = dict(bundle['consumers'])
    if 'cka-simulator' not in result['consumers']:
        result['consumers']['cka-simulator'] = 'soc1_' + random32()
    validate(result)
    return result


def enable_football(bundle: dict) -> dict:
    """Explicit Football-only opt-in; preserve every established key and consumer."""
    validate(bundle)
    result = dict(bundle)
    result['consumers'] = dict(bundle['consumers'])
    if 'football' not in result['consumers']:
        result['consumers']['football'] = 'soc1_' + random32()
    validate(result)
    return result


def enable_pawn_action(bundle: dict) -> dict:
    """Explicit staging-only Pawn Action opt-in; preserve existing Vault material."""
    validate(bundle)
    result = dict(bundle)
    result['consumers'] = dict(bundle['consumers'])
    if 'pawn-action' not in result['consumers']:
        result['consumers']['pawn-action'] = 'soc1_' + random32()
    validate(result)
    return result
