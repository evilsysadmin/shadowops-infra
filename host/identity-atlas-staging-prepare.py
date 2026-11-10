#!/opt/shadowops/oci-venv/bin/python -I
"""Prepare separate Atlas staging files; never read local Mongo Vault custody."""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_custody import derived_configs
from identity_staging_atlas import _connection
from identity_staging_atlas_lock import exclusive as atlas_lock

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


def prepare_files(root, service, custody, service_uid=65532, backup_uid=0, database_scoped=False):
    if service.get('admin_inventory_access_history') is not True:
        raise PrepareError('Existing staging inventory history configuration required')
    service_config, backup_config = derived_configs(custody, service)
    if database_scoped:
        service_config['mongo_privilege_mode'] = 'database-scoped'
    service_path = root / 'atlas-service.json'
    backup_path = root / 'atlas-backup.json'
    service_exists = _same_file(service_path, service_config, service_uid)
    backup_exists = _same_file(backup_path, backup_config, backup_uid)
    if not service_exists:
        _write_new(service_path, service_config, service_uid)
    if not backup_exists:
        _write_new(backup_path, backup_config, backup_uid)


def candidate_is_mounted(path, runner=subprocess.run):
    """Fail closed if any running Docker bind mount can expose the candidate."""
    def docker(args):
        result = runner(args, capture_output=True, text=True, timeout=20,
                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        if result.returncode != 0 or len(result.stdout) > 1048576:
            raise PrepareError('Cannot verify Atlas candidate mounts')
        return result.stdout
    ids = docker(['docker', 'ps', '--quiet', '--no-trunc']).splitlines()
    if not ids:
        return False
    if len(ids) > 256 or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in ids):
        raise PrepareError('Invalid running container inventory')
    lines = docker(['docker', 'inspect', '--format', '{{json .Mounts}}', *ids]).splitlines()
    if len(lines) != len(ids):
        raise PrepareError('Incomplete running container inventory')
    target = os.path.realpath(path)
    target_stat = path.stat()
    for line in lines:
        mounts = json.loads(line)
        if not isinstance(mounts, list):
            raise PrepareError('Invalid container mounts')
        for mount in mounts:
            if not isinstance(mount, dict):
                raise PrepareError('Invalid container mounts')
            if mount.get('Type') != 'bind':
                continue
            source = mount.get('Source')
            if not isinstance(source, str) or not os.path.isabs(source):
                raise PrepareError('Invalid bind mount')
            source = os.path.realpath(source)
            try:
                meta = os.stat(source)
                if (os.path.commonpath([target, source]) == source or
                    (meta.st_dev == target_stat.st_dev and meta.st_ino == target_stat.st_ino)):
                    return True
            except (OSError, ValueError):
                raise PrepareError('Cannot verify bind mount') from None
    return False


def refresh_inventory_candidate(root, service, custody, *, service_uid=65532, backup_uid=0, is_in_use=None):
    """Replace only an inactive Atlas candidate's inventory credential.

    Preserve the old private candidate as a hard-link checkpoint. A caller must
    hold the staging deploy lock and provide a fail-closed mount check.
    """
    if is_in_use is None:
        raise PrepareError('Active-use admission is required')
    service_path = root / 'atlas-service.json'
    backup_path = root / 'atlas-backup.json'
    if service.get('admin_inventory_access_history') is not True:
        raise PrepareError('Existing staging inventory history configuration required')
    desired, backup = derived_configs(custody, service)
    desired['mongo_privilege_mode'] = 'database-scoped'
    current = load_private(service_path, service_uid)
    if not _same_file(backup_path, backup, backup_uid):
        raise PrepareError('Atlas backup configuration must already exist')
    old_uri = current.get('admin_inventory_mongo_uri')
    new_uri = desired.get('admin_inventory_mongo_uri')
    try:
        if _connection(old_uri) != _connection(new_uri):
            raise PrepareError('Inventory identity changed')
    except ValueError:
        raise PrepareError('Invalid inventory identity') from None
    current_other = dict(current)
    desired_other = dict(desired)
    current_other.pop('admin_inventory_mongo_uri', None)
    desired_other.pop('admin_inventory_mongo_uri', None)
    if current_other != desired_other:
        raise PrepareError('Unrelated candidate configuration changed')
    if current == desired:
        return
    if is_in_use(service_path):
        raise PrepareError('Active Atlas candidate cannot be rotated')
    fd, temp = tempfile.mkstemp(dir=root, prefix='.atlas-inventory-')
    try:
        os.fchmod(fd, 0o400)
        os.fchown(fd, service_uid, service_uid)
        with os.fdopen(fd, 'w') as stream:
            json.dump(desired, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        # Do not replace the running candidate: retain the exact old inode as
        # a private checkpoint before an atomic rename.
        checkpoint = root / ('.atlas-service-previous-' + os.urandom(12).hex())
        os.link(service_path, checkpoint, follow_symlinks=False)
        os.replace(temp, service_path)
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in {'prepare', 'prepare-database-scoped', 'refresh-inventory', 'check-inventory-inactive'} or not VAULT.fullmatch(sys.argv[2]):
            raise PrepareError('Invalid Atlas staging preparation request')
        trusted_dir(ROOT)
        trusted_dir(STATE)
        with atlas_lock(STATE):
            if sys.argv[1] == 'check-inventory-inactive':
                load_private(ROOT / 'atlas-service.json', 65532)
                if candidate_is_mounted(ROOT / 'atlas-service.json'):
                    raise PrepareError('Active Atlas candidate cannot be rotated')
                print('IDENTITY_ATLAS_STAGING_CONFIG_PREPARED')
                return 0
            current = load_private(ROOT / 'service.json', 65532)
            custody = read_atlas_custody(sys.argv[2])
            if sys.argv[1] == 'refresh-inventory':
                refresh_inventory_candidate(ROOT, current, custody, is_in_use=candidate_is_mounted)
            else:
                prepare_files(ROOT, current, custody, database_scoped=sys.argv[1] == 'prepare-database-scoped')
        print('IDENTITY_ATLAS_STAGING_CONFIG_PREPARED')
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_STAGING_PREPARE_BLOCKED type=' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
