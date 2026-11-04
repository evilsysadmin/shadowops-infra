#!/opt/shadowops/oci-venv/bin/python -I
"""Prepare separate Atlas staging files; never read local Mongo Vault custody."""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_custody import derived_configs

ROOT = Path('/etc/shadowops/identity-staging')
STATE = Path('/var/lib/shadowops/identity-staging')
VAULT = re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')
SECRET = 'identity-staging-atlas-custody'

class PrepareError(ValueError):
    pass


def trusted_dir(path):
    for item in (path, *path.parents):
        meta = item.lstat()
        if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise PrepareError('Untrusted Atlas staging directory')


def load_private(path, owner):
    meta = path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or meta.st_uid != owner
            or meta.st_mode & 0o077 or meta.st_size > 131072):
        raise PrepareError('Invalid private service configuration')
    def no_duplicates(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise PrepareError('Ambiguous private service configuration')
            output[key] = value
        return output
    try:
        value = json.loads(path.read_text(), object_pairs_hook=no_duplicates)
    except (OSError, ValueError, TypeError):
        raise PrepareError('Invalid private service configuration') from None
    if not isinstance(value, dict):
        raise PrepareError('Invalid private service configuration')
    return value


def read_atlas_custody(vault):
    import oci
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    client = oci.secrets.SecretsClient(config={}, signer=signer)
    bundle = client.get_secret_bundle_by_name(secret_name=SECRET, vault_id=vault, stage='CURRENT').data
    raw = base64.b64decode(bundle.secret_bundle_content.content, validate=True)
    if len(raw) > 24000:
        raise PrepareError('Invalid Atlas custody')
    return json.loads(raw)


def _same_file(path, data, uid):
    if not path.exists() and not path.is_symlink():
        return False
    value = load_private(path, uid)
    if value != data:
        raise PrepareError('Atlas configuration rotation requires a separate operation')
    return True


def _write_new(path, data, uid):
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.atlas-prepare-')
    try:
        os.fchmod(fd, 0o400)
        os.fchown(fd, uid, uid)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        # Hard link refuses replacement even if another process creates the
        # destination after our preflight; both names are on the same filesystem.
        os.link(temp, path, follow_symlinks=False)
    finally:
        Path(temp).unlink(missing_ok=True)


def prepare_files(root, service, custody, service_uid=65532, backup_uid=0):
    if service.get('admin_inventory_access_history') is not True:
        raise PrepareError('Existing staging inventory history configuration required')
    service_config, backup_config = derived_configs(custody, service)
    service_path = root / 'atlas-service.json'
    backup_path = root / 'atlas-backup.json'
    service_exists = _same_file(service_path, service_config, service_uid)
    backup_exists = _same_file(backup_path, backup_config, backup_uid)
    if not service_exists:
        _write_new(service_path, service_config, service_uid)
    if not backup_exists:
        _write_new(backup_path, backup_config, backup_uid)


def main():
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] != 'prepare' or not VAULT.fullmatch(sys.argv[2]):
            raise PrepareError('Invalid Atlas staging preparation request')
        trusted_dir(ROOT)
        trusted_dir(STATE)
        with (STATE / 'deploy.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = load_private(ROOT / 'service.json', 65532)
            custody = read_atlas_custody(sys.argv[2])
            prepare_files(ROOT, current, custody)
        print('IDENTITY_ATLAS_STAGING_CONFIG_PREPARED')
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_STAGING_PREPARE_BLOCKED type=' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
