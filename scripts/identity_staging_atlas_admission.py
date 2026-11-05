"""Fail-closed verification of the Atlas backup required before cutover."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import stat

from identity_staging_atlas_backup import validate_backup_config
from identity_staging_backup import BackupError, MAX_BYTES, decrypt_snapshot


def require_recent_atlas_backup(config, state, now=None, expected_uid=0):
    """Verify private receipt and actual authenticated snapshot for this cluster.

    This only verifies existing files and never creates backups or changes the
    service. A separate live restore test and connection preflight are required.
    """
    try:
        validate_backup_config(config)
        state = Path(state)
        directory = state / 'atlas-backups'
        receipt_path = state / 'last-atlas-backup.json'
        for path in (state, directory, receipt_path):
            meta = path.lstat()
            if stat.S_ISLNK(meta.st_mode) or meta.st_uid != expected_uid or meta.st_mode & 0o077:
                raise BackupError('Private Atlas backup required')
        if not stat.S_ISDIR(state.stat().st_mode) or not stat.S_ISDIR(directory.stat().st_mode):
            raise BackupError('Private Atlas backup required')
        meta = receipt_path.stat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 8192:
            raise BackupError('Private Atlas backup required')
        receipt = json.loads(receipt_path.read_text())
        instant = now or datetime.now(timezone.utc)
        created = datetime.fromisoformat(receipt['created_at'])
        cluster_hash = hashlib.sha256(config['host'].encode()).hexdigest()
        if (instant.tzinfo is None or created.tzinfo is None or created > instant + timedelta(minutes=5)
                or instant - created > timedelta(hours=24) or receipt.get('schema') != 1
                or receipt.get('environment') != 'staging' or receipt.get('backend') != 'atlas'
                or receipt.get('cluster_sha256') != cluster_hash
                or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('sha256',''))
                or type(receipt.get('encrypted_bytes')) is not int
                or not 0 < receipt['encrypted_bytes'] <= 2*MAX_BYTES):
            raise BackupError('Recent Atlas backup required')
        files = list(directory.glob('*.fernet'))
        if len(files) > 10000:
            raise BackupError('Atlas backup inventory exceeds bound')
        for path in files:
            meta = path.lstat()
            if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or meta.st_uid != expected_uid
                    or meta.st_mode & 0o077 or meta.st_size != receipt['encrypted_bytes']):
                continue
            encrypted = path.read_bytes()
            if hashlib.sha256(encrypted).hexdigest() != receipt['sha256']:
                continue
            snapshot=decrypt_snapshot(encrypted, config['backup_key'])
            if snapshot['schema'] != 2:
                raise BackupError('Atlas schema 2 backup required')
            return {'snapshot':snapshot,'sha256':receipt['sha256'],'cluster_sha256':cluster_hash}
        raise BackupError('Authenticated Atlas backup not found')
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        raise BackupError('Recent authenticated Atlas backup required') from None
