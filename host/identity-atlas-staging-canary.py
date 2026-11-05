#!/opt/shadowops/oci-venv/bin/python -I
"""Start a short-lived, loopback-only staging Atlas service canary.

Starts the real service, so it may create its normal staging indexes. It does
not register accounts, grant roles, route public traffic or replace a service.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader

sys.path.insert(0, '/usr/local/lib/shadowops')
from identity_staging_atlas_admission import require_recent_atlas_backup

ROOT=Path('/etc/shadowops/identity-staging')
STATE=Path('/var/lib/shadowops/identity-staging')
CONFIG=ROOT/'atlas-service.json'
BACKUP=ROOT/'atlas-backup.json'
CA=ROOT/'ca.pem'
IMAGE='ghcr.io/evilsysadmin/shadowops-identity@'
DIGEST=re.compile(r'sha256:[a-f0-9]{64}')
SHA=re.compile(r'[a-f0-9]{40}')
PORT=re.compile(r'127\.0\.0\.1:([0-9]{1,5})\n?')

class CanaryError(ValueError): pass


def run(args, timeout=120):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','NO_PROXY':'*'})
    if result.returncode or len(result.stdout)>65536:
        raise CanaryError('Fixed canary command failed')
    return result.stdout


def read_private_json(path, uid):
    meta=path.lstat()
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or meta.st_uid!=uid or meta.st_mode&0o077 or meta.st_size>131072:
        raise CanaryError('Invalid private canary file')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise CanaryError('Ambiguous private canary file')
            result[key]=value
        return result
    value=json.loads(path.read_text(),object_pairs_hook=unique)
    if not isinstance(value,dict): raise CanaryError('Invalid private canary file')
    return value


def execute(digest, sha, *, runner=run, nonce=None, pause=time.sleep, journey=None):
    if not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha): raise CanaryError('Invalid image')
    suffix=nonce if nonce is not None else secrets.token_hex(12)
    if not re.fullmatch(r'[a-f0-9]{24}',suffix): raise CanaryError('Invalid canary identity')
    name='shadowops-identity-atlas-canary-'+suffix
    network='shadowops-identity-atlas-canary-net-'+suffix
    image=IMAGE+digest
    runner(['docker','pull',image])
    labels=json.loads(runner(['docker','image','inspect',image,'--format','{{json .Config.Labels}}']))
    if not isinstance(labels,dict) or labels.get('org.opencontainers.image.revision')!=sha or labels.get('org.opencontainers.image.source')!='https://github.com/evilsysadmin/shadowops-infra':
        raise CanaryError('Image source mismatch')
    net_attempted=False
    container_attempted=False
    try:
        net_attempted=True
        runner(['docker','network','create','--label','shadowops.identity.atlas-canary=staging',network])
        # Only loopback is published. The existing public tunnel and service
        # are not in this network, and no credential enters argv or logs.
        container_attempted=True
        runner(['docker','run','--detach','--name',name,'--network',network,
            '--publish','127.0.0.1::9443','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges:true','--pids-limit','128',
            '--memory','256m','--user','65532:65532',
            '--mount','type=bind,src='+str(CONFIG)+',dst=/run/secrets/identity-staging.json,readonly',image])
        endpoint=runner(['docker','port',name,'9443/tcp'])
        match=PORT.fullmatch(endpoint)
        if not match or not 1024<=int(match.group(1))<=65535: raise CanaryError('Invalid loopback endpoint')
        port=match.group(1)
        def get(path):
            return runner(['curl','--fail','--silent','--show-error','--noproxy','*','--max-time','5',
                '--cacert',str(CA),'--resolve','id-staging.shadowops.dpdns.org:'+port+':127.0.0.1',
                '--header','Host: id-staging.shadowops.dpdns.org',
                'https://id-staging.shadowops.dpdns.org:'+port+path],timeout=10)
        for _ in range(30):
            try:
                get('/readyz')
                break
            except CanaryError:
                pause(1)
        else: raise CanaryError('Canary not ready')
        page=get('/admin')
        if 'Administración de cuentas' not in page: raise CanaryError('Admin page unavailable')
        status=runner(['curl','--silent','--show-error','--noproxy','*','--max-time','5',
            '--cacert',str(CA),'--resolve','id-staging.shadowops.dpdns.org:'+port+':127.0.0.1',
            '--header','Host: id-staging.shadowops.dpdns.org',
            '--header','Origin: https://id-staging.shadowops.dpdns.org',
            '--header','Content-Type: application/json','--request','POST','--data','{}',
            '--output','/dev/null','--write-out','%{http_code}',
            'https://id-staging.shadowops.dpdns.org:'+port+'/api/identity/admin/accounts'],timeout=10)
        if status!='401': raise CanaryError('Unauthenticated admin access not denied')
        if journey is not None:
            if journey(int(port), network, CA, read_private_json(CONFIG,65532)) != 'IDENTITY_ATLAS_ADMIN_JOURNEY_OK':
                raise CanaryError('Synthetic admin journey failed')
    finally:
        try:
            if container_attempted:
                names=runner(['docker','ps','--all','--filter','name=^/'+name+'$','--format','{{.Names}}']).splitlines()
                if names == [name]: runner(['docker','rm','-f',name],timeout=30)
                elif names: raise CanaryError('Unexpected canary container')
        finally:
            if net_attempted:
                names=runner(['docker','network','ls','--filter','name=^'+network+'$','--format','{{.Name}}']).splitlines()
                if names == [network]: runner(['docker','network','rm',network],timeout=30)
                elif names: raise CanaryError('Unexpected canary network')
    marker='IDENTITY_ATLAS_ADMIN_CANARY_OK' if journey is not None else 'IDENTITY_ATLAS_LOOPBACK_CANARY_OK'
    return marker+' source_sha='+sha+' digest='+digest


def recover(*, runner=run, nonce=None):
    """Resolve a recorded synthetic account; ambiguous identities stay blocked."""
    from identity_staging_atlas_journey import JourneyCheckpoint, recover_pending
    checkpoint=JourneyCheckpoint()
    pending=checkpoint._read()
    if pending['subject'] is None:
        print('IDENTITY_ATLAS_CANARY_MANUAL_REVIEW_REQUIRED name='+pending['name'],file=sys.stderr)
        raise CanaryError('Ambiguous registration needs manual review')
    config=read_private_json(CONFIG,65532)
    suffix=nonce if nonce is not None else secrets.token_hex(12)
    if not re.fullmatch(r'[a-f0-9]{24}',suffix): raise CanaryError('Invalid recovery identity')
    network='shadowops-identity-atlas-canary-net-'+suffix
    attempted=False
    try:
        attempted=True
        runner(['docker','network','create','--label','shadowops.identity.atlas-canary-recovery=staging',network])
        return recover_pending(checkpoint,config.get('admin_inventory_mongo_uri'),network)
    finally:
        if attempted:
            names=runner(['docker','network','ls','--filter','name=^'+network+'$','--format','{{.Name}}']).splitlines()
            if names==[network]: runner(['docker','network','rm',network],timeout=30)
            elif names: raise CanaryError('Unexpected recovery network')


def main():
    try:
        if os.geteuid()!=0 or not ((len(sys.argv)==2 and sys.argv[1]=='recover') or (len(sys.argv)==4 and sys.argv[1] in {'canary','journey'})): raise CanaryError('Invalid request')
        spec=importlib.util.spec_from_loader('atlas_preflight',SourceFileLoader('atlas_preflight','/usr/local/sbin/shadowops-identity-atlas-preflight'))
        preflight=importlib.util.module_from_spec(spec);spec.loader.exec_module(preflight)
        preflight.trusted_paths()
        ca=CA.lstat()
        if stat.S_ISLNK(ca.st_mode) or not stat.S_ISREG(ca.st_mode) or ca.st_uid!=65532 or ca.st_mode&0o077:
            raise CanaryError('Invalid canary CA')
        with (STATE/'deploy.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if sys.argv[1]=='recover':
                print(recover())
                return 0
            backup=read_private_json(BACKUP,0)
            require_recent_atlas_backup(backup,STATE)
            preflight.execute(sys.argv[2],sys.argv[3])
            journey=None
            if sys.argv[1]=='journey':
                from identity_staging_atlas_journey import perform
                journey=perform
            print(execute(sys.argv[2],sys.argv[3],journey=journey))
        return 0
    except Exception as exc:
        print('IDENTITY_ATLAS_LOOPBACK_CANARY_BLOCKED type='+type(exc).__name__,file=sys.stderr)
        return 1

if __name__=='__main__': raise SystemExit(main())
