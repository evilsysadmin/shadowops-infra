#!/opt/shadowops/oci-venv/bin/python -I
"""Fixed Identity staging snapshots. Only backup is delegated; restore is operator-only."""
from __future__ import annotations
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0,'/usr/local/lib/shadowops')
from identity_staging_bundle import validate
from identity_staging_backup import BackupError, MAX_BYTES, encrypt_snapshot, decrypt_snapshot, export_script, restore_script

STATE=Path('/var/lib/shadowops/identity-staging')
DIRECTORY=STATE/'backups'
VAULT=re.compile(r'ocid1\.vault\.[A-Za-z0-9._-]{10,200}')
CONTAINER=re.compile(r'[a-f0-9]{12,64}')


def run(args,data=None):
    result=subprocess.run(args,input=data,text=True,capture_output=True,timeout=90,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
    if result.returncode != 0 or len(result.stdout.encode())>MAX_BYTES:
        raise BackupError('Fixed Identity snapshot operation failed')
    return result.stdout


def private_directory(path):
    if path.is_symlink():raise BackupError('Unsafe private directory')
    path.mkdir(mode=0o700,parents=False,exist_ok=True)
    meta=path.stat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077:
        raise BackupError('Private root directory required')


def write_private(path,data):
    if path.is_symlink():raise BackupError('Unsafe snapshot destination')
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.backup-')
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)


def operator_bundle(vault):
    import oci
    signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    client=oci.secrets.SecretsClient(config={},signer=signer)
    bundle=client.get_secret_bundle_by_name(secret_name='identity-staging-operator-bundle',vault_id=vault,stage='CURRENT').data
    raw=base64.b64decode(bundle.secret_bundle_content.content,validate=True)
    if len(raw)>24000:raise BackupError('Invalid operator custody')
    value=json.loads(raw);validate(value);return value


def mongo_container():
    ids=run(['docker','ps','-q','--filter','label=com.docker.compose.project=shadowops-identity-staging',
        '--filter','label=com.docker.compose.service=identity-mongo']).splitlines()
    if len(ids)!=1 or not CONTAINER.fullmatch(ids[0]):raise BackupError('One running Identity database required')
    return ids[0]


def mongo_script(container,script):
    return run(['docker','exec','-i',container,'mongosh','--quiet','--norc','--tls','--tlsCAFile',
        '/run/identity/ca.pem','mongodb://127.0.0.1:27017/?directConnection=true','--file','/dev/stdin'],script)


def main():
    try:
        if os.geteuid()!=0:raise BackupError('Root operator mechanism required')
        args=sys.argv[1:]
        if len(args)==1 and args[0]=='scheduled':
            args=['backup',(STATE/'backup-vault').read_text().strip()]
        if len(args) not in (2,3) or args[0] not in {'backup','restore'} or not VAULT.fullmatch(args[1]) or (args[0]=='backup' and len(args)!=2) or (args[0]=='restore' and len(args)!=3):
            raise BackupError('Invalid staging snapshot request')
        private_directory(STATE);private_directory(DIRECTORY)
        with (STATE/'deploy.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            bundle=operator_bundle(args[1]);container=mongo_container()
            if args[0]=='backup':
                value=json.loads(mongo_script(container,export_script(bundle['mongo_root_password'])).strip())
                encrypted=encrypt_snapshot(value,bundle['backup_key'])
                # Verify the written format before recording a successful backup.
                if decrypt_snapshot(encrypted,bundle['backup_key'])!=value:raise BackupError('Snapshot roundtrip failed')
                filename=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(6).hex()+'.fernet'
                write_private(DIRECTORY/filename,encrypted)
                receipt={'schema':1,'environment':'staging','created_at':datetime.now(timezone.utc).isoformat(),
                    'encrypted_bytes':len(encrypted),'sha256':hashlib.sha256(encrypted).hexdigest()}
                write_private(STATE/'last-backup.json',(json.dumps(receipt)+'\n').encode())
                write_private(STATE/'backup-vault',(args[1]+'\n').encode())
                print('IDENTITY_STAGING_BACKUP_OK encrypted_bytes='+str(len(encrypted)))
            else:
                active=run(['docker','ps','-q','--filter','label=com.docker.compose.project=shadowops-identity-staging',
                    '--filter','label=com.docker.compose.service=identity']).strip()
                if active:raise BackupError('Restore requires the Identity app stopped')
                path=Path(args[2])
                if not path.is_absolute() or path.is_symlink():raise BackupError('Private operator snapshot required')
                meta=path.stat()
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077 or meta.st_size>2*MAX_BYTES:
                    raise BackupError('Private bounded snapshot required')
                value=decrypt_snapshot(path.read_bytes(),bundle['backup_key'])
                output=mongo_script(container,restore_script(bundle['mongo_root_password'],value)).strip()
                if output!='IDENTITY_STAGING_QUARANTINE_RESTORE_OK':raise BackupError('Restore receipt missing')
                print(output)
    except Exception as exc:
        print('IDENTITY_STAGING_SNAPSHOT_BLOCKED type='+type(exc).__name__,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
