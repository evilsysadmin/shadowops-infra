#!/opt/shadowops/oci-venv/bin/python -I
"""Fixed read-only staging Atlas connectivity preflight; no Vault or cutover."""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_lock import exclusive as atlas_lock

ROOT=Path('/etc/shadowops/identity-staging')
STATE=Path('/var/lib/shadowops/identity-staging')
CONFIG=ROOT/'atlas-service.json'
SNOOKER_CONFIG=ROOT/'atlas-snooker-service.json'
IMAGE='ghcr.io/evilsysadmin/shadowops-identity@'
DIGEST=re.compile(r'sha256:[a-f0-9]{64}')
SHA=re.compile(r'[a-f0-9]{40}')

class PreflightError(ValueError):
    pass


def run(args,timeout=120):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
    if result.returncode != 0 or len(result.stdout)>65536:
        raise PreflightError('Fixed Atlas preflight failed')
    return result.stdout


def trusted_paths():
    for path in (ROOT, STATE):
        for item in (path,*path.parents):
            meta=item.lstat()
            if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
                raise PreflightError('Untrusted Atlas preflight path')
    meta=CONFIG.lstat()
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or meta.st_uid!=65532 or meta.st_mode&0o077 or meta.st_size>131072:
        raise PreflightError('Invalid Atlas staging configuration')


def execute(digest,sha,runner=run,nonce=None,config_path=CONFIG):
    if not isinstance(digest,str) or not DIGEST.fullmatch(digest) or not isinstance(sha,str) or not SHA.fullmatch(sha):
        raise PreflightError('Invalid immutable preflight request')
    # The isolated path is selected only by the reviewed Atlas release operator;
    # the existing standalone preflight continues to use the legacy config.
    if config_path not in (CONFIG, SNOOKER_CONFIG):
        raise PreflightError('Untrusted Atlas preflight config')
    meta=config_path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != 65532 or meta.st_mode & 0o077 or meta.st_size > 131072):
        raise PreflightError('Invalid Atlas preflight configuration')
    image=IMAGE+digest
    runner(['docker','pull',image])
    labels=json.loads(runner(['docker','image','inspect',image,'--format','{{json .Config.Labels}}']))
    if not isinstance(labels,dict) or labels.get('org.opencontainers.image.revision')!=sha or labels.get('org.opencontainers.image.source')!='https://github.com/evilsysadmin/shadowops-infra':
        raise PreflightError('Preflight image source mismatch')
    suffix=nonce if nonce is not None else secrets.token_hex(12)
    if not re.fullmatch(r'[a-f0-9]{24}',suffix):
        raise PreflightError('Invalid preflight network')
    network='shadowops-identity-atlas-probe-'+suffix
    created=False
    try:
        runner(['docker','network','create','--label','shadowops.identity.atlas-preflight=staging',network])
        created=True
        # Config is a fixed read-only file; no credential is placed in argv,
        # environment, OCI command output or Docker labels.
        runner(['docker','run','--rm','--network',network,'--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','--pids-limit','128','--memory','256m',
                '--user','65532:65532','--mount','type=bind,src='+str(config_path)+',dst=/run/secrets/identity-staging.json,readonly',
                image,'preflight'],timeout=60)
    finally:
        if created:
            runner(['docker','network','rm',network],timeout=30)
    return 'IDENTITY_ATLAS_PREFLIGHT_OK source_sha='+sha+' digest='+digest


def main():
    try:
        if os.geteuid()!=0 or len(sys.argv)!=4 or sys.argv[1]!='preflight':
            raise PreflightError('Invalid Atlas preflight request')
        trusted_paths()
        with atlas_lock(STATE):
            print(execute(sys.argv[2],sys.argv[3]))
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_PREFLIGHT_BLOCKED type='+type(exc).__name__,file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
