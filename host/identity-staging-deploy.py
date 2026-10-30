#!/usr/bin/env python3
"""Root-owned Identity staging release only. Fixed files/project, no caller shell or secrets."""
from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_bundle import BundleError, DATABASE, service_config, validate
from shared_a1_host_guard import verify_shared_a1_containers

ROOT = Path('/etc/shadowops/identity-staging')
STATE = Path('/var/lib/shadowops/identity-staging')
POLICY = ROOT / 'compose.yaml'
PROJECT = 'shadowops-identity-staging'
SERVICES = {'identity', 'identity-mongo', 'identity-tunnel'}
IMAGE = 'ghcr.io/evilsysadmin/shadowops-identity@'
MONGO_IMAGE = 'mongo@sha256:8bb4442761a63a8dda452744082cdac9644b429807eb977b42324a63cef59ca4'
TUNNEL_IMAGE = 'cloudflare/cloudflared@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4'
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
SHA = re.compile(r'[a-f0-9]{40}')
VAULT = re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')
SDK = '/opt/shadowops/oci-venv/bin/python'
VAULT_READER = '''
import base64, os, oci
signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
client=oci.secrets.SecretsClient(config={},signer=signer)
b=client.get_secret_bundle_by_name(secret_name="identity-staging-operator-bundle",vault_id=os.environ["VAULT_ID"],stage="CURRENT").data
print(b.secret_bundle_content.content)
'''


class DeployError(ValueError):
    pass


def request(operation, digest, sha, vault):
    if operation != 'deploy' or not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha) or not VAULT.fullmatch(vault):
        raise DeployError('Invalid fixed release request')


def trusted(path):
    for current in (path, *path.parents):
        meta = current.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise DeployError('Untrusted installed release policy')


def run(args, *, env=None, data=None, timeout=240, runner=subprocess.run):
    result = runner(args, env=env or {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, input=data,
                    text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 512000:
        raise DeployError('Fixed Identity operation failed')
    return result.stdout


def read_bundle(vault, runner=subprocess.run):
    encoded = run([SDK, '-I', '-c', VAULT_READER], env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'VAULT_ID': vault}, timeout=60, runner=runner)
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
        if len(raw) > 24000:
            raise ValueError('oversize')
        value = json.loads(raw)
        validate(value)
        return value
    except (ValueError, TypeError, KeyError):
        raise DeployError('Invalid private Identity Vault bundle') from None


def write_private(path, data, uid=0):
    if path.is_symlink():
        raise DeployError('Unsafe private destination')
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.identity-')
    try:
        os.fchmod(fd, 0o400)
        os.fchown(fd, uid, uid)
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def prepare(bundle):
    validate(bundle)
    mongo = ROOT / 'mongo'
    if mongo.is_symlink():
        raise DeployError('Unsafe database configuration directory')
    mongo.mkdir(mode=0o500, exist_ok=True)
    os.chown(mongo, 999, 999)
    os.chmod(mongo, 0o500)
    write_private(mongo / 'replica.key', bundle['mongo_replica_key'], 999)
    write_private(mongo / 'mongo.pem', bundle['mongo_certificate_key_pem'], 999)
    write_private(mongo / 'ca.pem', bundle['ca_certificate_pem'], 999)
    write_private(ROOT / 'service.json', json.dumps(service_config(bundle)), 65532)
    write_private(ROOT / 'ca.pem', bundle['ca_certificate_pem'], 65532)
    write_private(ROOT / 'tunnel.env', "TUNNEL_TOKEN='" + bundle['tunnel_token'] + "'\n")


def bootstrap_script(bundle):
    # Private script travels on stdin, never in OCI commands, argv or logs.
    # The localhost exception can initialize ONLY an empty database. A wrong
    # credential on an existing database fails rather than replacing users.
    prefix = 'const rootPassword=' + json.dumps(bundle['mongo_root_password']) + ';\n'
    prefix += 'const appPassword=' + json.dumps(bundle['mongo_application_password']) + ';\n'
    return prefix + '''
const hello=db.adminCommand({hello:1});
if (hello.setName && hello.setName !== 'identity-staging-rs') throw new Error('wrong replica');
if (!hello.setName) {
  const init=rs.initiate({_id:'identity-staging-rs',members:[{_id:0,host:'identity-mongo:27017'}]});
  if (init.ok !== 1) throw new Error('replica initialization failed');
}
for (let i=0; i<60 && !db.hello().isWritablePrimary; i++) sleep(1000);
if (!db.hello().isWritablePrimary) throw new Error('no primary');
const admin=db.getSiblingDB('admin');
function authenticated(result) { return result === true || result === 1 || (result && result.ok === 1); }
try {
  if (!authenticated(admin.auth('identity_root',rootPassword))) throw new Error('not authenticated');
} catch (_) {
  admin.createUser({user:'identity_root',pwd:rootPassword,roles:[{role:'root',db:'admin'}]});
  if (!authenticated(admin.auth('identity_root',rootPassword))) throw new Error('root authentication failed');
}
const stage=db.getSiblingDB('shadowops_identity_staging');
const privileges=[
 {resource:{db:stage.getName(),collection:'pending_accounts'},actions:['find','insert','update','createIndex','listIndexes']},
 {resource:{db:stage.getName(),collection:'sessions'},actions:['find','insert','update','remove','createIndex','listIndexes']},
 {resource:{db:stage.getName(),collection:'staging_cka_tokens'},actions:['find','insert','update','createIndex','listIndexes']}
];
if (stage.getRole('identity_runtime')) stage.updateRole('identity_runtime',{roles:[],privileges});
else stage.createRole({role:'identity_runtime',roles:[],privileges});
if (stage.getUser('identity_runtime')) {
  // Never reset a live database password during a normal release.
  if (!authenticated(stage.auth('identity_runtime',appPassword))) throw new Error('application credential mismatch');
} else stage.createUser({user:'identity_runtime',pwd:appPassword,roles:[{role:'identity_runtime',db:stage.getName()}]});
print('IDENTITY_STAGING_DATABASE_READY');
'''


def assert_compose(config, digest):
    if config.get('name') != PROJECT or set(config.get('services', {})) != SERVICES:
        raise DeployError('Wrong Identity project')
    images = {'identity': IMAGE + digest, 'identity-mongo': MONGO_IMAGE, 'identity-tunnel': TUNNEL_IMAGE}
    for name, service in config['services'].items():
        if service.get('image') != images[name] or service.get('platform') != 'linux/arm64':
            raise DeployError('Unadmitted image')
        if service.get('ports') or service.get('network_mode') or service.get('privileged') or service.get('devices') or service.get('pid') or service.get('build'):
            raise DeployError('Unexpected host authority')
        if service.get('read_only') is not True or service.get('cap_drop') != ['ALL'] or 'no-new-privileges:true' not in service.get('security_opt', []):
            raise DeployError('Container hardening missing')
        expected_user = '999:999' if name == 'identity-mongo' else '65532:65532'
        if service.get('user') != expected_user:
            raise DeployError('Wrong runtime user')
        allowed = {
            'identity': {('/etc/shadowops/identity-staging/service.json', '/run/secrets/identity-staging.json', 'bind', True)},
            'identity-mongo': {('identity-data', '/data/db', 'volume', False), ('/etc/shadowops/identity-staging/mongo', '/run/identity', 'bind', True)},
            'identity-tunnel': {('/etc/shadowops/identity-staging/ca.pem', '/run/identity/ca.pem', 'bind', True)},
        }
        mounts = {(v.get('source'), v.get('target'), v.get('type'), bool(v.get('read_only'))) for v in service.get('volumes', [])}
        if mounts != allowed[name]:
            raise DeployError('Unexpected filesystem authority')
    networks = config.get('networks', {})
    if set(networks) != {'database', 'origin', 'tunnel-egress'} or networks['database'].get('internal') is not True or networks['origin'].get('internal') is not True:
        raise DeployError('Identity network isolation missing')


def assert_existing_identity_containers(rows):
    counts = {}
    for row in rows:
        labels = row.get('Labels') or {}
        if labels.get('com.docker.compose.project') != PROJECT:
            continue
        service = labels.get('com.docker.compose.service')
        counts[service] = counts.get(service, 0) + 1
        if service not in SERVICES or counts[service] > 1 or row.get('Bindings'):
            raise DeployError('Identity project collision or published port')


def identity_ownership_guard():
    # Inspect only labels and configured port bindings, including stopped containers.
    ids = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT]).splitlines()
    if len(ids) > 3 or any(not re.fullmatch('[a-f0-9]{12,64}', value) for value in ids):
        raise DeployError('Ambiguous Identity containers')
    if ids:
        rows = run(['docker', 'inspect', '--format', '{"Labels":{{json .Config.Labels}},"Bindings":{{json .HostConfig.PortBindings}}}', *ids])
        assert_existing_identity_containers([json.loads(line) for line in rows.splitlines()])
    # Never adopt an existing foreign volume/network with a matching name.
    resources = [('volume', PROJECT + '-data')] + [('network', PROJECT + '-' + n) for n in ('database', 'origin', 'tunnel-egress')]
    for kind, name in resources:
        found = run(['docker', kind, 'ls', '--filter', 'name=^' + name + '$', '--format', '{{.Name}}']).splitlines()
        if not found:
            continue
        if found != [name]:
            raise DeployError('Ambiguous Identity resource')
        labels = json.loads(run(['docker', kind, 'inspect', name, '--format', '{{json .Labels}}'])) or {}
        if labels.get('com.docker.compose.project') != PROJECT:
            raise DeployError('Identity resource already owned elsewhere')


def deploy(digest, sha, vault):
    request('deploy', digest, sha, vault)
    if os.geteuid() != 0:
        raise DeployError('Root-owned operator installation required')
    trusted(POLICY)
    trusted(STATE)
    for path in (ROOT, STATE):
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
            raise DeployError('Private root directory required')
    with (STATE / 'deploy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_shared_a1_containers()
        identity_ownership_guard()
        bundle = read_bundle(vault)
        prepare(bundle)
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'IDENTITY_IMAGE_DIGEST': digest}
        compose = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(POLICY)]
        config = json.loads(run(compose + ['config', '--format', 'json'], env=env))
        assert_compose(config, digest)
        # Only our exact Compose project. Never stack with another file or delete a volume.
        run(compose + ['pull', 'identity-mongo', 'identity', 'identity-tunnel'], env=env)
        labels = json.loads(run(['docker', 'image', 'inspect', IMAGE + digest, '--format', '{{json .Config.Labels}}'])) or {}
        if labels.get('org.opencontainers.image.revision') != sha or labels.get('org.opencontainers.image.source') != 'https://github.com/evilsysadmin/shadowops-infra':
            raise DeployError('Image source receipt does not match the admitted request')
        verify_shared_a1_containers()
        identity_ownership_guard()
        run(compose + ['up', '-d', '--no-build', '--no-deps', 'identity-mongo'], env=env)
        container = run(compose + ['ps', '-q', 'identity-mongo'], env=env).strip()
        if not re.fullmatch('[a-f0-9]{12,64}', container):
            raise DeployError('Ambiguous Identity database container')
        # mongod may still be starting. All retries are bounded and scoped to our container.
        import time
        for attempt in range(30):
            try:
                run(['docker','exec',container,'mongosh','--quiet','--norc','--tls','--tlsCAFile','/run/identity/ca.pem',
                     'mongodb://127.0.0.1:27017/?directConnection=true','--eval','if (db.adminCommand({ping:1}).ok !== 1) quit(1)'], timeout=5)
                break
            except DeployError:
                if attempt == 29:
                    raise
                time.sleep(1)
        run(['docker', 'exec', '-i', container, 'mongosh', '--quiet', '--norc', '--tls', '--tlsCAFile',
             '/run/identity/ca.pem', 'mongodb://127.0.0.1:27017/?directConnection=true', '--file', '/dev/stdin'],
            data=bootstrap_script(bundle), timeout=100)
        run(compose + ['up', '-d', '--wait', '--wait-timeout', '150', '--no-build', '--pull', 'never', '--force-recreate', 'identity', 'identity-tunnel'], env=env)
        write_private(STATE / 'last-started.json', json.dumps({'source_sha': sha, 'digest': digest, 'public_login_verified': False}) + '\n')
        print('IDENTITY_STAGING_SERVICE_STARTED source_sha=' + sha + ' digest=' + digest)


def main():
    try:
        if len(sys.argv) != 5:
            raise DeployError('Expected fixed deploy request')
        request(*sys.argv[1:])
        deploy(*sys.argv[2:])
    except Exception as exc:
        print('IDENTITY_STAGING_DEPLOY_BLOCKED type=' + type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
