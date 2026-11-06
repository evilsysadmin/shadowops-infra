#!/opt/shadowops/oci-venv/bin/python -I
"""Operator-only Atlas staging update; no local Mongo custody or tunnel changes.

The caller must independently admit the immutable image and its provenance.
This initial operator is deliberately not installed or delegated by workflows.
"""
import fcntl
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_admission import require_recent_atlas_backup
from identity_staging_atlas_policy import validate_atlas_compose
from identity_staging_atlas_transition import current_atlas_image, TransitionCheckpoint, transition
from shared_a1_host_guard import verify_shared_a1_containers

ROOT = Path('/etc/shadowops/identity-staging')
STATE = Path('/var/lib/shadowops/identity-staging')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
SHA = re.compile(r'[a-f0-9]{40}')
PROJECT = 'shadowops-identity-staging'


class DeployError(ValueError):
    pass


def run(args, *, digest=None, timeout=180):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'NO_PROXY': '*'}
    if digest is not None:
        env['IDENTITY_IMAGE_DIGEST'] = digest
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode or len(result.stdout) > 1048576:
        raise DeployError('Fixed Atlas deployment operation failed')
    return result.stdout


def load_operator(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def require_root_file(path, forbidden):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & forbidden:
        raise DeployError('Trusted Atlas operator file required')


def update(digest, sha, *, runner=run, preflight=None, backup_operator=None, checkpoint=None):
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise DeployError('Invalid immutable image')
    preflight = preflight or load_operator('atlas_preflight', '/usr/local/sbin/shadowops-identity-atlas-preflight')
    backup_operator = backup_operator or load_operator('atlas_backup', '/usr/local/sbin/shadowops-identity-atlas-backup')
    preflight.trusted_paths()
    require_root_file(STATE / 'atlas-active', 0o077)
    require_root_file(ROOT / 'atlas-compose.yaml', 0o022)
    backup = backup_operator.private_config()
    require_recent_atlas_backup(backup, STATE)
    verify_shared_a1_containers()
    ids = runner(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project='+PROJECT,
                  '--filter', 'label=com.docker.compose.service=identity']).splitlines()
    if len(ids) != 1 or not re.fullmatch(r'[a-f0-9]{12,64}', ids[0]):
        raise DeployError('Ambiguous Identity container')
    old = current_atlas_image(json.loads(runner(['docker', 'inspect', ids[0]])))
    preflight.execute(digest, sha)
    compose = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'atlas-compose.yaml')]
    config = json.loads(runner(compose + ['config', '--format', 'json'], digest=digest))
    validate_atlas_compose(config, digest)
    def activate(image):
        runner(compose + ['up', '-d', '--no-deps', '--wait', '--wait-timeout', '150',
               '--no-build', '--pull', 'never', '--force-recreate', 'identity'], digest=image, timeout=180)
    def verify(image):
        ids = runner(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project='+PROJECT,
                      '--filter', 'label=com.docker.compose.service=identity']).splitlines()
        if len(ids) != 1 or not re.fullmatch(r'[a-f0-9]{12,64}', ids[0]):
            return False
        if current_atlas_image(json.loads(runner(['docker', 'inspect', ids[0]]))) != image:
            return False
        runner(['curl', '--silent', '--show-error', '--fail', '--noproxy', '*', '--max-time', '10',
                'https://id-staging.shadowops.dpdns.org/readyz'], timeout=15)
        return True
    transition(old, digest, checkpoint or TransitionCheckpoint(STATE), activate, verify)
    return 'IDENTITY_ATLAS_DEPLOY_OK source_sha='+sha+' digest='+digest


def main():
    try:
        if os.geteuid() != 0 or len(sys.argv) != 4 or sys.argv[1] != 'deploy':
            raise DeployError('Invalid operator request')
        with (STATE / 'deploy.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(update(sys.argv[2], sys.argv[3]))
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_DEPLOY_BLOCKED type='+type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
