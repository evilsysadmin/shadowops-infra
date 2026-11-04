"""Fixed Atlas staging snapshot transport; never prints credentials or plaintext."""
import json
import re
import subprocess

from identity_staging_backup import BackupError, MAX_BYTES, atlas_export_script, encrypt_snapshot

IMAGE = 'mongo@sha256:8bb4442761a63a8dda452744082cdac9644b429807eb977b42324a63cef59ca4'
NETWORK = 'shadowops-identity-staging-atlas-egress'
DATABASE = 'shadowops_identity_staging'


def validate_backup_config(value):
    if (not isinstance(value, dict) or set(value) != {'environment', 'host', 'username', 'password', 'backup_key'}
            or value['environment'] != 'staging' or not isinstance(value['host'], str)
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.mongodb\.net', value['host'])
            or '..' in value['host']):
        raise BackupError('Invalid Atlas backup configuration')
    # Validation also ensures a fixed, distinct operator username and bounded password.
    atlas_export_script(value['username'], value['password'])
    if not isinstance(value['backup_key'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}=', value['backup_key']):
        raise BackupError('Invalid Atlas backup configuration')


def snapshot(value, runner=subprocess.run):
    """Return an encrypted snapshot; Docker receives credentials only on stdin.

    Caller must hold the shared deployment lock and verify ownership of the
    fixed network. Never log subprocess output or exceptions.
    """
    validate_backup_config(value)
    uri = 'mongodb+srv://' + value['host'] + '/' + DATABASE + '?tls=true&authSource=admin'
    args = ['docker', 'run', '--rm', '-i', '--network', NETWORK,
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--pids-limit', '64', '--memory', '256m', '--user', '999:999',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '-e', 'HOME=/tmp',
            '--entrypoint', 'mongosh', IMAGE, '--quiet', '--norc', uri, '--file', '/dev/stdin']
    try:
        result = runner(args, input=atlas_export_script(value['username'], value['password']),
                        text=True, capture_output=True, timeout=90,
                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout.encode()) > MAX_BYTES:
            raise BackupError('Atlas snapshot failed')
        return encrypt_snapshot(json.loads(result.stdout), value['backup_key'])
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise BackupError('Atlas snapshot failed') from None
