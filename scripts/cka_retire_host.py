#!/usr/bin/python3 -I
"""Operator-only removal of CKA from the shared A1. No cloud authority."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys

LAB_USER='shadowops-cka-lab'
LAB_ROOT=Path('/var/lib/shadowops-cka-lab-staging')
LAB_CONFIG=Path('/etc/cka-lab-staging')
ACCOUNT=Path('/etc/shadowops/cka-account-staging')
ACCOUNT_STATE=Path('/var/lib/shadowops/cka-account-staging')
IDENTITY=Path('/etc/shadowops/identity-staging/service.json')
CF_IMAGE='cloudflare/cloudflared@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4'

class RetireError(ValueError):pass

def run(args,*,timeout=60):
    value=subprocess.run(args,text=True,capture_output=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    if value.returncode or len(value.stdout)>2_000_000:raise RetireError('Fixed retirement operation failed: '+args[0])
    return value.stdout.strip()

def trusted(path,*,owner=0):
    info=path.lstat()
    if path.is_symlink() or info.st_uid!=owner or info.st_mode&0o022:raise RetireError('Untrusted CKA path')
    return info

def inspect(docker):
    ids=run([*docker,'ps','-aq']).splitlines()
    return json.loads(run([*docker,'inspect',*ids])) if ids else []

def validate_container(value,*,rootless=False):
    labels=value.get('Config',{}).get('Labels') or {}
    project=labels.get('com.docker.compose.project')
    service=labels.get('com.docker.compose.service')
    image=value.get('Config',{}).get('Image','')
    if rootless and value.get('Name')=='/cka-lab-staging-control-plane':
        if labels.get('io.x-k8s.kind.cluster')!='cka-lab-staging' or not image.startswith('kindest/node:v1.35.0@sha256:'):
            raise RetireError('Foreign node in dedicated daemon')
        return
    expected='shadowops-cka-lab-staging' if rootless else 'shadowops-cka-account-staging'
    if project!=expected or service not in ({'cka-lab','cka-lab-tunnel'} if rootless else {'cka-account','cka-account-tunnel'}):
        raise RetireError('Foreign container; refusing retirement')
    if service.endswith('tunnel'):
        if image!=CF_IMAGE:raise RetireError('Foreign connector image')
    elif not re.fullmatch(r'ghcr.io/evilsysadmin/cka-'+('lab' if rootless else 'account')+r'-staging@sha256:[a-f0-9]{64}',image):
        raise RetireError('Foreign CKA image')
    expected_root=str(LAB_ROOT/'runtime/home') if rootless else str(ACCOUNT)
    for mount in value.get('Mounts',[]):
        if mount.get('Type')=='bind' and not (mount.get('Source','').startswith(expected_root+'/') or (rootless and mount.get('Source','').startswith(str(LAB_ROOT/'runtime/home')+'/'))):
            raise RetireError('Foreign CKA bind mount')

def host_plan():
    host=['docker','--host','unix:///var/run/docker.sock']
    all_host=inspect(host)
    account=[v for v in all_host if (v.get('Config',{}).get('Labels') or {}).get('com.docker.compose.project')=='shadowops-cka-account-staging']
    for item in account:validate_container(item)
    lab=None
    try:user=pwd.getpwnam(LAB_USER)
    except KeyError:user=None
    receipt=LAB_CONFIG/'policy.json'
    if user:
        if (user.pw_dir!=str(LAB_ROOT/'runtime/home') or user.pw_shell!='/usr/sbin/nologin'
                or user.pw_uid==0 or os.getgrouplist(LAB_USER,user.pw_gid)!=[user.pw_gid]):raise RetireError('Foreign lab identity')
        trusted(receipt)
        policy=json.loads(receipt.read_text())
        if policy.get('uid')!=user.pw_uid or policy.get('gid')!=user.pw_gid:raise RetireError('Lab policy identity mismatch')
        for name,digest in policy['files'].items():
            path=Path(name)
            allowed=(str(path).startswith('/usr/local/libexec/cka-lab-staging/') or name in {
                '/usr/local/sbin/shadowops-cka-lab-staging','/etc/systemd/user/cka-lab-rootless-docker.service',
                '/etc/sudoers.d/107-shadowops-cka-lab-staging','/etc/cka-lab-staging/daemon.json','/etc/cka-lab-staging/runc.env',
                '/etc/systemd/system/shadowops-cka-lab-disk.service',
                f'/etc/systemd/system/user@{user.pw_uid}.service.d/cka-lab-runtime.conf',
                f'/etc/systemd/system/user-{user.pw_uid}.slice.d/cka-lab-limits.conf'})
            if not allowed:raise RetireError('Foreign managed policy path')
            if path.exists():
                trusted(path)
                if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise RetireError('Modified managed policy; operator review needed')
        socket=f'unix:///run/user/{user.pw_uid}/cka-lab-docker.sock'
        daemon=['runuser','-u',LAB_USER,'--','docker','--host',socket]
        if Path(f'/run/user/{user.pw_uid}/cka-lab-docker.sock').exists():
            info=json.loads(run([*daemon,'info','--format','{{json .}}']))
            if info.get('DockerRootDir')!=str(LAB_ROOT/'runtime/docker') or 'name=rootless' not in info.get('SecurityOptions',[]):
                raise RetireError('Wrong rootless daemon')
            containers=inspect(daemon)
            for value in containers:validate_container(value,rootless=True)
        else:containers=[]
        image=LAB_ROOT/'runtime.ext4'
        trusted(image)
        if image.stat().st_size!=8*1024**3:raise RetireError('Unexpected lab disk')
        if os.path.ismount(LAB_ROOT/'runtime'):
            mount=json.loads(run(['findmnt','--json','--mountpoint',str(LAB_ROOT/'runtime'),'-o','TARGET,SOURCE,FSTYPE,OPTIONS']))['filesystems']
            if len(mount)!=1 or mount[0]['fstype']!='ext4' or not re.fullmatch(r'/dev/loop[0-9]+',mount[0]['source']):raise RetireError('Unexpected lab mount')
            backing=run(['losetup','--noheadings','--output','BACK-FILE',mount[0]['source']])
            if backing!=str(image):raise RetireError('Foreign mounted disk')
        lab=(user,policy,daemon,containers)
    elif receipt.exists() or LAB_ROOT.exists():raise RetireError('Orphan lab data; cannot infer ownership')
    factory_unit=Path('/etc/systemd/system/shadowops-cka-factory-staging.service')
    factory_dirs=[Path('/opt/shadowops/cka-factory-staging'),Path('/var/lib/shadowops/cka-factory-staging')]
    try:factory_user=pwd.getpwnam('shadowops-cka-factory')
    except KeyError:factory_user=None
    factory=bool(factory_unit.exists() or any(p.exists() for p in factory_dirs) or factory_user)
    if factory:
        trusted(factory_unit)
        expected=Path('/opt/shadowops-infra/host/cka-factory-staging.service')
        if factory_unit.read_bytes()!=expected.read_bytes():raise RetireError('Modified factory unit')
        if factory_user and (factory_user.pw_uid==0 or factory_user.pw_shell!='/usr/sbin/nologin'):
            raise RetireError('Foreign factory identity')
        for path in factory_dirs:
            if path.exists():trusted(path,owner=factory_user.pw_uid if factory_user and str(path).startswith('/var/lib/') else 0)
    # Preserve every other running/stopped product and its state.
    other={v['Id']:(v['State']['Status'],v['State'].get('StartedAt')) for v in all_host if v not in account
           and not ((v.get('Config',{}).get('Labels') or {}).get('com.docker.compose.project')=='shadowops-identity-staging' and (v.get('Config',{}).get('Labels') or {}).get('com.docker.compose.service')=='identity')}
    identity=[v for v in all_host if (v.get('Config',{}).get('Labels') or {}).get('com.docker.compose.project')=='shadowops-identity-staging'
              and (v.get('Config',{}).get('Labels') or {}).get('com.docker.compose.service')=='identity']
    if IDENTITY.exists():
        trusted(IDENTITY,owner=65532)
        config=json.loads(IDENTITY.read_text())
        if type(config.get('consumers')) is not dict or 'chronicles' not in config['consumers']:raise RetireError('Unknown shared Identity config')
        if len(identity)!=1 or not identity[0]['Config']['Image'].startswith('ghcr.io/evilsysadmin/shadowops-identity@sha256:'):raise RetireError('Unknown shared Identity service')
    else:config=None
    return host,account,lab,other,identity,config,factory

def remove_tree(path):
    if not path.exists():return
    if path.is_symlink() or os.path.ismount(path):raise RetireError('Unsafe retirement directory')
    # Refuse any nested mounts before recursively removing private data.
    mounts=json.loads(run(['findmnt','--json','--list','-o','TARGET']))['filesystems']
    if any(v['target'].startswith(str(path)+'/') for v in mounts):raise RetireError('Nested mount remains')
    shutil.rmtree(path)

def retire(plan):
    host,account,lab,other,identities,config,factory=plan
    if account:run([*host,'rm','--force',*[v['Id'] for v in account]])
    if lab:
        user,policy,daemon,containers=lab
        if containers:run([*daemon,'rm','--force',*[v['Id'] for v in containers]],timeout=150)
        # Only the dedicated nologin user and its manager/slice are stopped.
        run(['loginctl','disable-linger',LAB_USER])
        run(['systemctl','stop',f'user@{user.pw_uid}.service'],timeout=90)
        for proc in Path('/proc').iterdir():
            if proc.name.isdecimal():
                try:
                    if proc.stat().st_uid==user.pw_uid:raise RetireError('Lab processes remain')
                except FileNotFoundError:pass
        run(['systemctl','disable','--now','shadowops-cka-lab-disk.service'])
        if os.path.ismount(LAB_ROOT/'runtime'):raise RetireError('Lab disk still mounted')
        for name in policy['files']:Path(name).unlink(missing_ok=True)
        # userdel removes only this system account and its subordinate ranges;
        # no shared Docker package, kernel setting or system library is uninstalled.
        run(['userdel',LAB_USER])
        run(['groupdel',LAB_USER]) if any(line.startswith(LAB_USER+':') for line in Path('/etc/group').read_text().splitlines()) else None
        remove_tree(LAB_ROOT);remove_tree(LAB_CONFIG)
        lib=Path('/usr/local/libexec/cka-lab-staging')
        if lib.exists():lib.rmdir() # unexpected files block deletion
    for path in [ACCOUNT,ACCOUNT_STATE]:
        if path.exists():trusted(path);remove_tree(path)
    for path in ['/usr/local/sbin/shadowops-cka-account-staging','/usr/local/lib/shadowops/cka_account_contract.py','/etc/sudoers.d/106-shadowops-cka-account-staging']:
        p=Path(path)
        if p.exists():trusted(p);p.unlink()
    # Remove only the two owned host-daemon account networks, never Identity-origin.
    for name in ['shadowops-cka-account-staging-origin','shadowops-cka-account-staging-tunnel-egress']:
        ids=run([*host,'network','ls','-q','--filter','name=^'+name+'$']).splitlines()
        if ids:
            value=json.loads(run([*host,'network','inspect',name]))[0]
            if value.get('Labels',{}).get('com.docker.compose.project')!='shadowops-cka-account-staging' or value.get('Containers'):
                raise RetireError('Foreign or busy account network')
            run([*host,'network','rm',name])
    if config and 'cka-simulator' in config['consumers']:
        del config['consumers']['cka-simulator']
        # Preserve the bind-mounted inode; rewriting atomically then restarting
        # would leave Docker mounting the old credential file.
        with IDENTITY.open('r+') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX)
            stream.seek(0);json.dump(config,stream);stream.truncate();stream.flush();os.fsync(stream.fileno())
        run([*host,'restart',identities[0]['Id']],timeout=90)
        for _ in range(45):
            value=json.loads(run([*host,'inspect',identities[0]['Id']]))[0]
            if value['State'].get('Health',{}).get('Status')=='healthy':break
            import time;time.sleep(2)
        else:raise RetireError('Shared Identity did not become healthy')
    if factory:
        run(['systemctl','disable','--now','shadowops-cka-factory-staging.service'])
        for path in [Path('/opt/shadowops/cka-factory-staging'),Path('/var/lib/shadowops/cka-factory-staging')]:remove_tree(path)
        Path('/etc/systemd/system/shadowops-cka-factory-staging.service').unlink(missing_ok=True)
        try:pwd.getpwnam('shadowops-cka-factory')
        except KeyError:pass
        else:run(['userdel','shadowops-cka-factory'])
        if any(line.startswith('shadowops-cka-factory:') for line in Path('/etc/group').read_text().splitlines()):run(['groupdel','shadowops-cka-factory'])
    run(['systemctl','daemon-reload'])
    after={v['Id']:(v['State']['Status'],v['State'].get('StartedAt')) for v in inspect(host)}
    if any(after.get(k)!=v for k,v in other.items()):raise RetireError('Another product changed during retirement')
    print('CKA_RETIRE_HOST_REMOVED shared_products=unchanged identity_cka_consumer=removed')

def verify(plan):
    host,account,lab,other,identity,config,factory=plan
    if account or lab or factory or ACCOUNT.exists() or ACCOUNT_STATE.exists() or (config and 'cka-simulator' in config['consumers']):
        raise RetireError('CKA host resources remain')
    print('CKA_RETIRE_HOST_VERIFIED account=absent rootless_lab=absent shared_identity=preserved')

def main():
    if os.geteuid()!=0 or sys.argv[1:] not in (['retire'],['inspect']):raise RetireError('Operator root retire|inspect only')
    for parent in [Path(__file__).resolve(),*Path(__file__).resolve().parents]:trusted(parent)
    with Path('/run/lock/shadowops-cka-retire.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        plan=host_plan()
        if sys.argv[1]=='retire':retire(plan)
        verify(host_plan())

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('CKA_RETIRE_HOST_BLOCKED '+(str(error) if isinstance(error,RetireError) else 'type='+type(error).__name__),file=sys.stderr);raise SystemExit(1)
