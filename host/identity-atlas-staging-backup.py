#!/opt/shadowops/oci-venv/bin/python -I
"""Fixed, separately provisioned Atlas staging backup; never reads local Mongo custody."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_backup import snapshot, validate_backup_config
from identity_staging_backup import BackupError, decrypt_snapshot
from identity_staging_atlas_lock import exclusive as atlas_lock

STATE = Path('/var/lib/shadowops/identity-staging')
DIRECTORY = STATE / 'atlas-backups'
CONFIG = Path('/etc/shadowops/identity-staging/atlas-backup.json')


def trusted(path, directory=False):
    meta = path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077 or
            (directory and not stat.S_ISDIR(meta.st_mode)) or
            (not directory and (not stat.S_ISREG(meta.st_mode) or meta.st_size > 8192))):
        raise BackupError('Unsafe private Atlas backup path')


def private_config(path=CONFIG):
    # Every parent is root-owned and not group/world writable; config itself
    # remains private. Do not follow a symlink anywhere in its path.
    trusted(path)
    for parent in path.parents:
        meta = parent.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise BackupError('Unsafe Atlas backup configuration')
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BackupError('Ambiguous Atlas backup configuration')
            result[key] = value
        return result
    value = json.loads(path.read_text(), object_pairs_hook=no_duplicates)
    validate_backup_config(value)
    return value


def network_command(args):
    result = subprocess.run(['docker', 'network', *args], text=True, capture_output=True,
                            timeout=30, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    if result.returncode != 0:
        raise BackupError('Temporary Atlas backup network failed')


def capture_snapshot(config, command=network_command, capture=snapshot, nonce=None):
    suffix = nonce if nonce is not None else secrets.token_hex(12)
    if not re.fullmatch(r'[a-f0-9]{24}', suffix):
        raise BackupError('Invalid Atlas backup network')
    network = 'shadowops-identity-atlas-backup-' + suffix
    created = False
    try:
        command(['create', '--label', 'shadowops.identity.atlas-backup=staging', network])
        created = True
        return capture(config, network)
    finally:
        if created:
            command(['rm', network])


def write_private(path, data):
    if path.is_symlink():
        raise BackupError('Unsafe snapshot destination')
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.atlas-backup-')
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    try:
        if os.geteuid() != 0 or sys.argv[1:] not in (['backup'], ['rehearse']):
            raise BackupError('Invalid Atlas backup request')
        trusted(STATE, directory=True)
        DIRECTORY.mkdir(mode=0o700, exist_ok=True)
        trusted(DIRECTORY, directory=True)
        with atlas_lock(STATE):
            config = private_config()
            if sys.argv[1]=='rehearse':
                from identity_staging_atlas_admission import require_recent_atlas_backup
                from identity_staging_atlas_restore import rehearse, MARKER
                admitted=require_recent_atlas_backup(config,STATE)
                if rehearse(admitted['snapshot'])!=MARKER:
                    raise BackupError('Restore rehearsal receipt missing')
                receipt={'schema':1,'environment':'staging','backend':'atlas',
                    'created_at':datetime.now(timezone.utc).isoformat(),
                    'backup_sha256':admitted['sha256'],'cluster_sha256':admitted['cluster_sha256'],
                    'result':'quarantine-restore-verified'}
                write_private(STATE/'last-atlas-restore.json',(json.dumps(receipt)+'\n').encode())
                print(MARKER+' backup_sha256='+admitted['sha256'])
                return 0
            encrypted = capture_snapshot(config)
            decrypt_snapshot(encrypted, config['backup_key'])
            filename = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + os.urandom(6).hex() + '.fernet'
            write_private(DIRECTORY / filename, encrypted)
            receipt = {'schema': 1, 'environment': 'staging', 'backend': 'atlas',
                       'created_at': datetime.now(timezone.utc).isoformat(),
                       'cluster_sha256': hashlib.sha256(config['host'].encode()).hexdigest(),
                       'encrypted_bytes': len(encrypted), 'sha256': hashlib.sha256(encrypted).hexdigest()}
            write_private(STATE / 'last-atlas-backup.json', (json.dumps(receipt) + '\n').encode())
        print('IDENTITY_ATLAS_STAGING_BACKUP_OK encrypted_bytes=' + str(len(encrypted)))
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_STAGING_BACKUP_BLOCKED type=' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
