#!/usr/bin/python3 -I
"""Operator-only private controller: root reads the CKA consumer, lab user writes/runs.

No CLI-selected paths, contexts, image repositories, credentials or environments.
This module does not create a tunnel, host port, user account or public endpoint.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cka_account_contract import canonical32, public_keys
from cka_lab_cluster import verify_cluster
from cka_lab_rootless_policy import verify_daemon

REPO = Path('/opt/shadowops-infra')
HOME_DIR = Path('/var/lib/shadowops-cka-lab-staging/runtime/home')
USER = 'shadowops-cka-lab'
PROJECT = 'shadowops-cka-lab-staging'
IMAGE = 'ghcr.io/evilsysadmin/cka-lab-staging@'
HOST = 'cka-labs-staging.shadowops.dpdns.org'
ORIGIN = 'https://staging.cka.shadowops.dpdns.org'
JWKS = 'https://id-staging.shadowops.dpdns.org/api/identity/jwks'
SOURCE = 'evilsysadmin/cka-exam-simulator'
REQUIRED = {'CI', 'Go scenario contract', 'CKA restricted lab staging', 'CKA account staging'}
SHA = re.compile(r'[a-f0-9]{40}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
STAGE = 'preflight'


class ApiError(ValueError):
    pass


def stage(name):
    global STAGE
    STAGE = name
    print('CKA_LAB_PRIVATE_API_STAGE ' + name, flush=True)


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ApiError('Duplicate configuration field')
        result[name] = value
    return result


def decode(raw):
    if not isinstance(raw, (str, bytes)) or len(raw) > 24576:
        raise ApiError('Invalid bounded configuration')
    return json.loads(raw, object_pairs_hook=unique)


def release(value):
    if (type(value) is not dict or set(value) != {'schema', 'source_sha', 'image_digest'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['source_sha']) is not str or not SHA.fullmatch(value['source_sha'])
            or type(value['image_digest']) is not str or not DIGEST.fullmatch(value['image_digest'])):
        raise ApiError('Reviewed immutable release required')
    return value


def configuration(value, pin):
    if (type(value) is not dict or set(value) != {'environment', 'access_mode', 'build', 'jwks', 'service_credential'}
            or value['environment'] != 'staging' or value['access_mode'] != 'authenticated-staging'
            or value['build'] != pin['source_sha'] or type(value['service_credential']) is not str
            or not value['service_credential'].startswith('soc1_')
            or not canonical32(value['service_credential'][5:])):
        raise ApiError('Explicit authenticated CKA staging configuration required')
    public_keys(value['jwks'])
    return value


def root_path(path, *, uid=0, mode=None, maximum=24576):
    for parent in path.parents:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ApiError('Untrusted source ancestor')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or info.st_size > maximum or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or (mode is None and info.st_mode & 0o022)):
        raise ApiError('Untrusted fixed source')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def public_json(url):
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    agent = 'ShadowOps-CKA-Account-Provision/1' if url == JWKS else 'ShadowOps-CKA-Lab-Private/1'
    req = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': agent})
    with opener.open(req, timeout=15) as response:
        raw = response.read(1048577)
        if response.status != 200 or response.geturl() != url or len(raw) > 1048576:
            raise ApiError('Public release evidence unavailable')
    return json.loads(raw, object_pairs_hook=unique)


def source_checks(pin, reader=public_json):
    sha = pin['source_sha']
    commit = reader('https://api.github.com/repos/' + SOURCE + '/commits/main')
    runs = reader('https://api.github.com/repos/' + SOURCE + '/actions/runs?head_sha=' + sha + '&event=push&per_page=100')
    if commit.get('sha') != sha or not isinstance(runs.get('workflow_runs'), list):
        raise ApiError('Reviewed controller source is superseded')
    good = {r.get('name') for r in runs['workflow_runs']
            if r.get('head_sha') == sha and r.get('head_branch') == 'main' and r.get('event') == 'push'
            and r.get('status') == 'completed' and r.get('conclusion') == 'success'
            and r.get('repository', {}).get('full_name') == SOURCE}
    if not REQUIRED <= good:
        raise ApiError('Current protected controller CI is not green')


def handoff():
    if os.geteuid() != 0 or Path(__file__).resolve() != REPO / 'scripts/cka_lab_private_api.py':
        raise ApiError('Fixed protected operator checkout required')
    pin_path = REPO / 'deploy/cka-lab-staging-release.json'
    root_path(pin_path)
    pin = release(decode(pin_path.read_bytes()))
    stage('current-source-ci')
    source_checks(pin)
    stage('cka-consumer-handoff')
    source = Path('/etc/shadowops/cka-account-staging/account.json')
    # Existing account deployment deliberately owns this read-only file as 65532.
    root_path(source, uid=65532, mode=0o400)
    account = decode(source.read_bytes())
    if (type(account) is not dict or set(account) != {'environment', 'service_credential', 'jwks', 'identity_ca_pem', 'build'}
            or account['environment'] != 'staging' or type(account['build']) is not str
            or not SHA.fullmatch(account['build'])):
        raise ApiError('Existing isolated CKA account configuration required')
    public_keys(account['jwks'])
    keys = public_json(JWKS)
    public_keys(keys)
    value = configuration({'environment': 'staging', 'access_mode': 'authenticated-staging',
        'build': pin['source_sha'], 'jwks': keys, 'service_credential': account['service_credential']}, pin)
    # A private stdin pipe, not shell interpolation, env, argv, logs or an artifact.
    result = subprocess.run(['runuser', '--user', USER, '--', '/usr/bin/python3', '-I', str(Path(__file__)), 'start'],
        input=json.dumps(value), text=True, timeout=600,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if result.returncode:
        raise ApiError('Dedicated private controller start failed')


def private_directory(path, uid):
    if path.is_symlink():
        raise ApiError('Private directory required')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ApiError('Private directory required')


def private_file(path, value, uid):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ApiError('Private regular file required')
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.cka-private-')
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def compose_policy(document, pin, *, home=HOME_DIR, platform='linux/arm64', test_ca=None):
    services = document.get('services', {})
    if set(services) != {'cka-lab', 'cka-lab-tunnel'}:
        raise ApiError('Fixed private Compose services required')
    item = services['cka-lab']
    expected = {(str(home / 'config/lab.json'), '/run/secrets/cka-lab-staging.json', True),
                (str(home / 'cluster/controller.yaml'), '/run/secrets/cka-lab-admin.yaml', True),
                (str(home / 'controller-state'), '/var/lib/cka-lab', False)}
    if test_ca is not None:
        expected.add((str(test_ca), '/opt/runtime/certifi/cacert.pem', True))
    mounts = item.get('volumes', [])
    networks = document.get('networks', {})
    if (item.get('image') != IMAGE + pin['image_digest'] or item.get('platform') != platform
            or str(item.get('user')) != '0:0' or item.get('read_only') is not True
            or item.get('init') is not True or item.get('cap_drop') != ['ALL']
            or item.get('security_opt') not in (['no-new-privileges'], ['no-new-privileges:true'])
            or item.get('pids_limit') != 64 or float(item.get('cpus', 0)) != 0.1
            or str(item.get('mem_limit')).lower() not in {'256m', '268435456'}
            or str(item.get('memswap_limit')).lower() not in {'256m', '268435456'}
            or any(item.get(k) for k in ['ports', 'privileged', 'cap_add', 'network_mode', 'pid', 'ipc', 'uts',
                                       'devices', 'entrypoint', 'command', 'environment', 'build', 'depends_on', 'secrets', 'configs'])
            or item.get('sysctls') != {'net.ipv4.ip_forward': '0', 'net.ipv6.conf.all.forwarding': '0'}
            or set(item.get('networks', {})) != {'origin', 'cluster', 'identity-egress'}
            or networks.get('origin', {}).get('internal') is not True
            or networks.get('origin', {}).get('name') != 'shadowops-cka-lab-staging-origin'
            or networks.get('cluster', {}).get('external') is not True
            or networks.get('cluster', {}).get('name') != 'shadowops-cka-lab-staging-cluster'
            or networks.get('identity-egress', {}).get('name') != 'shadowops-cka-lab-staging-identity-egress'
            or len(mounts) != len(expected) or any(m.get('type') != 'bind' for m in mounts)
            or {(m.get('source'), m.get('target'), m.get('read_only', False)) for m in mounts} != expected):
        raise ApiError('Unsafe computed private controller policy')


def container_policy(row, pin, *, home=HOME_DIR, project=PROJECT, test_ca=None):
    policy, config = row['HostConfig'], row['Config']
    labels = config.get('Labels', {})
    expected = {(str(home / 'config/lab.json'), '/run/secrets/cka-lab-staging.json', False),
                (str(home / 'cluster/controller.yaml'), '/run/secrets/cka-lab-admin.yaml', False),
                (str(home / 'controller-state'), '/var/lib/cka-lab', True)}
    if test_ca is not None:
        # Only the disposable integration calls this pure validator with a CA.
        # The operator CLI has no corresponding override or argument.
        expected.add((str(test_ca), '/opt/runtime/certifi/cacert.pem', False))
    mounts = row.get('Mounts', [])
    if (config.get('Image') != IMAGE + pin['image_digest'] or config.get('User') != '0:0'
            or labels.get('com.docker.compose.project') != project
            or labels.get('com.docker.compose.service') != 'cka-lab'
            or not policy.get('ReadonlyRootfs') or policy.get('Privileged')
            or policy.get('CapAdd') or policy.get('CapDrop') != ['ALL']
            or policy.get('SecurityOpt') not in (['no-new-privileges'], ['no-new-privileges:true'])
            or policy.get('Memory') != 256 * 1024**2 or policy.get('MemorySwap') != 256 * 1024**2
            or policy.get('NanoCpus') != 100000000 or policy.get('PidsLimit') != 64
            or policy.get('PidMode') or policy.get('UTSMode') or policy.get('Devices') or policy.get('DeviceRequests')
            or policy.get('IpcMode', '') not in {'', 'private'}
            or policy.get('RestartPolicy', {}).get('Name') != 'unless-stopped'
            or policy.get('Sysctls', {}).get('net.ipv4.ip_forward') != '0'
            or policy.get('Sysctls', {}).get('net.ipv6.conf.all.forwarding') != '0'
            or any(row.get('NetworkSettings', {}).get('Ports', {}).values())
            or policy.get('Init') is not True or len(mounts) != len(expected)
            or set(row.get('NetworkSettings', {}).get('Networks', {})) != {
                'shadowops-cka-lab-staging-origin', 'shadowops-cka-lab-staging-cluster',
                'shadowops-cka-lab-staging-identity-egress'}):
        raise ApiError('Unsafe actual private controller')
    if (any(m.get('Type') != 'bind' for m in mounts)
            or {(m.get('Source'), m.get('Destination'), m.get('RW')) for m in mounts} != expected):
        raise ApiError('Unexpected private controller mounts')


PROBE = r'''
import json,sys,urllib.request,urllib.error
from pathlib import Path
host='cka-labs-staging.shadowops.dpdns.org'
origin='https://staging.cka.shadowops.dpdns.org'
group=Path('/sys/fs/cgroup')
assert int((group/'memory.max').read_text())==268435456
assert (group/'memory.swap.max').read_text().strip()=='0'
quota,period=map(int,(group/'cpu.max').read_text().split())
assert period>0 and 0<quota/period<=0.1
assert int((group/'pids.max').read_text())==64
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='0'
assert Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip()=='0'
with open('/run/secrets/cka-lab-staging.json') as source:config=json.load(source)
assert config['access_mode']=='authenticated-staging' and config['build']==sys.argv[1]
def request(path, body=None):
 headers={'Host':host}
 if body is not None:headers.update({'Origin':origin,'Content-Type':'application/json'})
 req=urllib.request.Request('http://127.0.0.1:8080'+path,data=body,headers=headers)
 try:
  with urllib.request.urlopen(req,timeout=5) as r:return r.status,r.read(4096)
 except urllib.error.HTTPError as e:return e.code,b''
assert request('/readyz')[0]==200
status,raw=request('/api/labs/release')
assert status==200 and json.loads(raw)=={'application':'cka-exam-simulator','build':sys.argv[1],'mode':'restricted-lab-pilot'}
assert request('/api/labs/capabilities',b'{}')[0]==401
assert request('/api/dev/lab/start',b'{}')[0]==404
print('CKA_LAB_PRIVATE_API_HEALTH_VERIFIED')
'''


def operate(action):
    account = pwd.getpwnam(USER)
    if os.geteuid() != account.pw_uid or account.pw_uid == 0 or account.pw_dir != str(HOME_DIR):
        raise ApiError('Dedicated lab runtime user required')
    if (HOME_DIR.is_symlink() or not HOME_DIR.is_dir() or HOME_DIR.stat().st_uid != account.pw_uid
            or stat.S_IMODE(HOME_DIR.stat().st_mode) != 0o700):
        raise ApiError('Existing private runtime home required')
    pin = release(decode((REPO / 'deploy/cka-lab-staging-release.json').read_bytes()))
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': account.pw_dir,
        'XDG_RUNTIME_DIR': '/run/user/' + str(account.pw_uid),
        'DOCKER_HOST': 'unix:///run/user/' + str(account.pw_uid) + '/cka-lab-docker.sock',
        'CKA_LAB_IMAGE_DIGEST': pin['image_digest']}
    def run(*args, timeout=30):
        result = subprocess.run(list(args), env=env, text=True, capture_output=True, timeout=timeout)
        if result.returncode or len(result.stdout) + len(result.stderr) > 1048576:
            raise ApiError('Fixed private controller command failed')
        return result.stdout.strip()
    verify_daemon(decode(run('docker', 'info', '--format', '{{json .}}')))
    verify_cluster(HOME_DIR / 'cluster', env=env)
    command = ['docker', 'compose', '--env-file', '/dev/null', '-p', PROJECT,
               '-f', str(REPO / 'compose.cka-lab.staging.yaml')]
    if action == 'start':
        value = configuration(decode(sys.stdin.read(24577)), pin)
        # First private activation only. Preserve any existing controller/state.
        if run('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT):
            raise ApiError('Existing controller requires inspection, not another initial start')
        memory = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:'))
        disk = os.statvfs(HOME_DIR)
        if memory < 512 * 1024 or disk.f_bavail * disk.f_frsize < 1024**3:
            raise ApiError('Insufficient private controller headroom')
        stage('pull-admitted-image')
        run('docker', 'pull', '--quiet', IMAGE + pin['image_digest'], timeout=300)
        image = json.loads(run('docker', 'image', 'inspect', IMAGE + pin['image_digest']))[0]
        if (image.get('Architecture') != 'arm64'
                or image.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.revision') != pin['source_sha']):
            raise ApiError('Admitted ARM64 source image required')
        stage('recheck-current-source')
        source_checks(pin)
        stage('write-private-config')
        private_directory(HOME_DIR / 'config', account.pw_uid)
        private_directory(HOME_DIR / 'controller-state', account.pw_uid)
        private_file(HOME_DIR / 'config/lab.json', json.dumps(value), account.pw_uid)
        tunnel = HOME_DIR / 'config/tunnel.env'
        if not tunnel.exists() and not tunnel.is_symlink():
            private_file(tunnel, '', account.pw_uid)
        stage('start-controller-only')
        compose_policy(json.loads(run(*command, 'config', '--no-env-resolution', '--format', 'json')), pin, home=HOME_DIR)
        run(*command, 'up', '--detach', '--no-deps', '--pull=never', '--wait', '--wait-timeout=150', 'cka-lab', timeout=180)
    stage('verify-controller')
    container = run(*command, 'ps', '--quiet', 'cka-lab')
    if not re.fullmatch(r'[a-f0-9]{12,64}', container):
        raise ApiError('Exactly one private controller required')
    row = json.loads(run('docker', 'inspect', container))[0]
    container_policy(row, pin, home=HOME_DIR)
    if run('docker', 'exec', container, 'python', '-c', PROBE, pin['source_sha']) != 'CKA_LAB_PRIVATE_API_HEALTH_VERIFIED':
        raise ApiError('Private controller health evidence unavailable')
    print('CKA_LAB_PRIVATE_API_VERIFIED ' + json.dumps({'schema': 1, **pin,
        'authenticated_staging_configured': True, 'anonymous_denied': True,
        'controller_healthy': True, 'public_endpoint_enabled': False, 'candidate_acceptance_verified': False}, sort_keys=True))


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {'handoff', 'start', 'verify'}:
            return 64
        if Path(__file__).resolve() != REPO / 'scripts/cka_lab_private_api.py':
            raise ApiError('Fixed protected source required')
        if sys.argv[1] == 'handoff':
            handoff()
        else:
            operate(sys.argv[1])
        return 0
    except Exception:
        print('CKA_LAB_PRIVATE_API_BLOCKED stage=' + STAGE, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
