#!/usr/bin/python3 -I
"""Fixed CKA account-only policy. No caller-selected shell, paths, image repo or environment."""
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

sys.path.insert(0, '/usr/local/lib/shadowops')
from cka_account_contract import AccountError, HOST, SECRET, PROJECT, IMAGE, TUNNEL_IMAGE, SHA, DIGEST, VAULT, validate, account_config
from shared_a1_host_guard import verify_shared_a1_containers

ROOT = Path('/etc/shadowops/cka-account-staging')
STATE = Path('/var/lib/shadowops/cka-account-staging')
POLICY = ROOT / 'compose.yaml'
SDK = '/opt/shadowops/oci-venv/bin/python'
TRUSTED = (Path('/usr/local/sbin/shadowops-cka-account-staging'),
           Path('/usr/local/lib/shadowops/cka_account_contract.py'),
           Path('/usr/local/lib/shadowops/identity_staging_bundle.py'), POLICY)
VAULT_READER = '''
import os, oci
signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
client=oci.secrets.SecretsClient(config={},signer=signer)
b=client.get_secret_bundle_by_name(secret_name="cka-account-staging-runtime",vault_id=os.environ["VAULT_ID"],stage="CURRENT").data
print(b.secret_bundle_content.content)
'''


def trusted(path):
    for item in (path, *path.parents):
        value=item.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise AccountError('Untrusted installed account policy')


def verify_policy():
    trusted(STATE / 'policy.json')
    receipt=json.loads((STATE / 'policy.json').read_text())
    if type(receipt.get('schema')) is not int or receipt.get('schema') != 1 or not SHA.fullmatch(receipt.get('source_sha','')):
        raise AccountError('Account policy receipt missing')
    hashes={}
    for path in TRUSTED:
        trusted(path)
        hashes[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    if receipt.get('files') != hashes: raise AccountError('Account policy receipt mismatch')
    return receipt['source_sha']


def run(args, *, env=None, data=None, timeout=240, runner=subprocess.run):
    result=runner(args,env=env or {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'},input=data,
                  text=True,capture_output=True,timeout=timeout)
    if result.returncode != 0 or not isinstance(result.stdout,str) or len(result.stdout) > 512000:
        raise AccountError('Fixed account command failed')
    return result.stdout


def private(path, value, uid=0):
    if path.is_symlink(): raise AccountError('Unsafe private account destination')
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.cka-account-')
    try:
        os.fchmod(fd,0o400);os.fchown(fd,uid,uid)
        with os.fdopen(fd,'w') as out:
            out.write(value);out.flush();os.fsync(out.fileno())
        os.replace(name,path)
    finally:
        Path(name).unlink(missing_ok=True)


def fresh_backup(now=None, *, path=Path('/var/lib/shadowops/identity-staging/last-backup.json')):
    trusted(path)
    if path.stat().st_size > 4096:raise AccountError('Invalid backup receipt')
    receipt=json.loads(path.read_text())
    # Match the existing Identity backup receipt, without reading any snapshot.
    completed=datetime.fromisoformat(receipt['created_at'].replace('Z','+00:00'))
    age=((now or datetime.now(timezone.utc))-completed).total_seconds()
    if (type(receipt.get('schema')) is not int or receipt.get('schema') != 1 or receipt.get('environment') != 'staging' or not 0 <= age <= 26*3600
            or type(receipt.get('encrypted_bytes')) is not int or receipt['encrypted_bytes'] <= 0
            or not re.fullmatch(r'[a-f0-9]{64}',receipt.get('sha256',''))):
        raise AccountError('Recent Identity backup required')


def memory_bytes(value):
    if type(value) is int:return value
    if not isinstance(value,str) or not re.fullmatch(r'[1-9][0-9]*[kmg]?',value.lower()):return 0
    text=value.lower();suffix=text[-1]
    return int(text[:-1])*{'k':1024,'m':1024**2,'g':1024**3}[suffix] if suffix in 'kmg' else int(text)


def compose_policy(document, digest):
    services=document.get('services',{})
    if set(services) != {'cka-account','cka-account-tunnel'}: raise AccountError('Unexpected account service')
    for name,item in services.items():
        image=IMAGE+digest if name=='cka-account' else TUNNEL_IMAGE
        if (item.get('image') != image or item.get('platform') != 'linux/arm64'
                or str(item.get('user')) != '65532:65532' or item.get('read_only') is not True
                or item.get('ports') or item.get('privileged') or item.get('network_mode')
                or item.get('cap_add') or item.get('cap_drop') != ['ALL']
                or item.get('init') is not True or item.get('devices')
                or item.get('pid') or item.get('ipc') or item.get('uts')
                or not 0 < item.get('pids_limit',0) <= 128
                or not 0 < memory_bytes(item.get('mem_limit',0)) <= 512*1024*1024
                or not 0 < float(item.get('cpus',0)) <= 1
                or item.get('security_opt') != ['no-new-privileges:true']):
            raise AccountError('Unsafe account container policy')
    if services['cka-account'].get('entrypoint') or services['cka-account'].get('command') or services['cka-account'].get('environment'):
        raise AccountError('Account image entrypoint and environment are fixed')
    if services['cka-account-tunnel'].get('command') != ['tunnel','--no-autoupdate','--metrics','127.0.0.1:20242','run']:
        raise AccountError('Tunnel command is fixed')
    networks=document.get('networks',{})
    if (set(networks)!={'origin','identity-origin','tunnel-egress'}
            or networks['origin'].get('name')!='shadowops-cka-account-staging-origin' or networks['origin'].get('internal') is not True
            or networks['identity-origin'].get('name')!='shadowops-identity-staging-origin' or networks['identity-origin'].get('external') is not True
            or set(services['cka-account'].get('networks',{}))!={'origin','identity-origin'}
            or set(services['cka-account-tunnel'].get('networks',{}))!={'origin','tunnel-egress'}):
        raise AccountError('Account private network boundary required')
    mounts=services['cka-account'].get('volumes',[])
    if (len(mounts) != 1 or mounts[0].get('source') != str(ROOT/'account.json')
            or mounts[0].get('target') != '/run/secrets/cka-account-staging.json'
            or mounts[0].get('read_only') is not True): raise AccountError('Unexpected account mount')
    if services['cka-account-tunnel'].get('volumes'): raise AccountError('Unexpected tunnel mount')


def verify_identity_network(rows):
    if (not isinstance(rows,list) or len(rows)!=1 or rows[0].get('Name')!='shadowops-identity-staging-origin'
            or rows[0].get('Internal') is not True
            or rows[0].get('Labels',{}).get('com.docker.compose.project')!='shadowops-identity-staging'):
        raise AccountError('Trusted internal Identity origin network required')


def existing_containers(rows):
    counts={}
    for row in rows:
        labels=row.get('Labels',{})
        name=labels.get('com.docker.compose.service')
        if (labels.get('com.docker.compose.project')!=PROJECT or name not in {'cka-account','cka-account-tunnel'}
                or row.get('Bindings') or row.get('Privileged') or row.get('NetworkMode') in {'host','none'}):
            raise AccountError('Unexpected existing account container')
        counts[name]=counts.get(name,0)+1
        if counts[name]>1:raise AccountError('Duplicate account container')
        mounts=row.get('Mounts',[])
        expected=[] if name=='cka-account-tunnel' else [(str(ROOT/'account.json'),'/run/secrets/cka-account-staging.json')]
        actual=[]
        for mount in mounts:
            if mount.get('Type')!='bind' or mount.get('RW') is not False:raise AccountError('Unsafe existing account mount')
            actual.append((mount.get('Source'),mount.get('Destination')))
        if actual!=expected:raise AccountError('Unexpected existing account mounts')


def verify_existing():
    ids=run(['docker','ps','-aq','--filter','label=com.docker.compose.project='+PROJECT]).split()
    if len(ids)>8 or any(not re.fullmatch(r'[a-f0-9]{12,64}',i) for i in ids):raise AccountError('Invalid account inventory')
    rows=[]
    fmt='{"Labels":{{json .Config.Labels}},"Bindings":{{json .HostConfig.PortBindings}},"Mounts":{{json .Mounts}},"Privileged":{{json .HostConfig.Privileged}},"NetworkMode":{{json .HostConfig.NetworkMode}}}'
    for identifier in ids:rows.append(json.loads(run(['docker','inspect','--format',fmt,identifier])))
    existing_containers(rows)


SMOKE = '''
import json,urllib.request,urllib.error,sys
host="cka-api-staging.shadowops.dpdns.org"
def get(path):
 r=urllib.request.Request("http://127.0.0.1:8080"+path,headers={"Host":host})
 try:
  with urllib.request.urlopen(r,timeout=3) as response:return response.status,response.read(4096)
 except urllib.error.HTTPError as error:return error.code,b""
assert get("/readyz")[0]==200
status,raw=get("/api/account/release")
assert status==200 and json.loads(raw)=={"application":"cka-exam-simulator","mode":"account-only-staging","build":sys.argv[1]}
assert get("/api/account/me")[0]==401
assert get("/api/dev/lab/start")[0]==404
assert get("/api/scenarios")[0]==404
'''


def deploy(digest,sha,vault):
    if not DIGEST.fullmatch(digest) or not SHA.fullmatch(sha) or not VAULT.fullmatch(vault):
        raise AccountError('Invalid fixed account release request')
    policy_sha=verify_policy();fresh_backup();verify_shared_a1_containers();verify_existing()
    verify_identity_network(json.loads(run(['docker','network','inspect','shadowops-identity-staging-origin'])))
    encoded=run([SDK,'-I','-c',VAULT_READER],env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','VAULT_ID':vault},timeout=60)
    raw=base64.b64decode(encoded.strip(),validate=True)
    if len(raw)>24000: raise AccountError('Oversized private account bundle')
    bundle=json.loads(raw);validate(bundle)
    private(ROOT/'account.json',json.dumps(account_config(bundle,sha)),65532)
    private(ROOT/'tunnel.env',"TUNNEL_TOKEN='"+bundle['tunnel_token']+"'\n")
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','CKA_ACCOUNT_IMAGE_DIGEST':digest}
    cmd=['docker','compose','-p',PROJECT,'-f',str(POLICY)]
    compose_policy(json.loads(run(cmd+['config','--format','json'],env=env)),digest)
    # No host ports, Docker socket, persistent volumes or lab credentials exist.
    run(cmd+['pull'],env=env,timeout=240)
    run(cmd+['up','-d','--wait','--wait-timeout','150'],env=env,timeout=180)
    run(cmd+['exec','-T','--user','65532:65532','cka-account','python','-c',SMOKE,sha],env=env,timeout=30)
    verify_shared_a1_containers();verify_existing()
    private(STATE/'release.json',json.dumps({'schema':1,'environment':'staging','source_sha':sha,
            'digest':digest,'policy_sha':policy_sha,'completed_at':datetime.now(timezone.utc).isoformat()}))
    print('CKA_ACCOUNT_STAGING_STARTED source_sha='+sha+' digest='+digest)


def stop():
    verify_policy();verify_shared_a1_containers();verify_existing()
    ids=run(['docker','ps','-q','--filter','label=com.docker.compose.project='+PROJECT]).split()
    if len(ids)>2 or any(not re.fullmatch(r'[a-f0-9]{12,64}',i) for i in ids):raise AccountError('Invalid account stop inventory')
    for identifier in ids:run(['docker','stop','--time','10',identifier],timeout=25)
    verify_shared_a1_containers();verify_existing()
    print('CKA_ACCOUNT_STAGING_STOPPED')


def main():
    try:
        if os.geteuid()!=0: raise AccountError('Root policy required')
        if sys.argv[1:]==['inspect']:
            print('CKA_ACCOUNT_STAGING_POLICY_OK source_sha='+verify_policy());return 0
        if sys.argv[1:]==['stop']:
            trusted(STATE)
            with (STATE/'.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX);stop()
            return 0
        if len(sys.argv)!=5 or sys.argv[1]!='deploy': raise AccountError('Invalid account operation')
        trusted(STATE)
        with (STATE/'.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX);deploy(*sys.argv[2:])
        return 0
    except Exception as error:
        print('CKA_ACCOUNT_STAGING_BLOCKED type='+type(error).__name__);return 1
if __name__=='__main__': raise SystemExit(main())
