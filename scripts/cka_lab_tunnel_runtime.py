"""Fixed operator tunnel handoff; the dedicated lab user runs the connector."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cka_lab_private_api as api
from cka_lab_tunnel import LOCATOR, SECRET, CF_IMAGE, CF_COMMAND, bundle, locator
from cka_lab_public import wait_api, verify_api

SDK = Path('/opt/shadowops/oci-venv/bin/python')
READ = '''
import oci,os
signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
client=oci.secrets.SecretsClient(config={'region':'eu-frankfurt-1'},signer=signer)
value=client.get_secret_bundle_by_name(secret_name='cka-lab-staging-tunnel',vault_id=os.environ['VAULT_ID'],stage='CURRENT').data
print(value.secret_bundle_content.content)
'''


def read_locator(pin):
    agent = pwd.getpwnam('ocarun').pw_uid
    fd = os.open(LOCATOR, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != agent or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 2048):
            raise api.ApiError('Private nonsecret locator metadata required')
        return locator(api.decode(stream.read(2049)), pin)


def read_bundle(location, pin):
    # The existing venv interpreter may be a root-owned symlink to system Python.
    for parent in SDK.parents:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise api.ApiError('Trusted existing OCI SDK required')
    if SDK.lstat().st_uid != 0:
        raise api.ApiError('Trusted existing OCI SDK required')
    api.root_path(SDK.resolve(), maximum=64 * 1024**2)
    api.stage('read-encrypted-lab-tunnel-token')
    result = subprocess.run([str(SDK), '-I', '-c', READ], capture_output=True, text=True, timeout=90,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'VAULT_ID': location['vault_id']})
    if result.returncode or len(result.stdout) > 16384:
        raise api.ApiError('Narrow lab token read failed')
    value = bundle(api.decode(base64.b64decode(result.stdout.strip(), validate=True)), pin)
    if value['tunnel_id'] != location['tunnel_id']:
        raise api.ApiError('Tunnel custody and locator differ')
    return value


def handoff():
    if os.geteuid() != 0:
        raise api.ApiError('Operator root handoff required')
    pin = api.release(api.decode((api.REPO / 'deploy/cka-lab-staging-release.json').read_bytes()))
    api.stage('verify-current-controller-source')
    api.source_checks(pin)
    api.stage('wait-nonsecret-locator')
    deadline = time.monotonic() + 360
    while True:
        try:
            location = read_locator(pin)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise api.ApiError('Launch the manual publication workflow first') from None
            time.sleep(3)
    value = read_bundle(location, pin)
    api.stage('start-dedicated-connector')
    result = subprocess.run(['runuser', '--user', api.USER, '--', '/usr/bin/python3', '-I', str(Path(__file__)), 'start'],
        input=json.dumps(value), text=True, timeout=900,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if result.returncode:
        raise api.ApiError('Dedicated lab connector failed')


def tunnel_policy(row, *, project=api.PROJECT, token=None):
    config, host = row['Config'], row['HostConfig']
    labels = config.get('Labels', {})
    if token is not None and [item for item in config.get('Env', []) if item.startswith('TUNNEL_TOKEN=')] != ['TUNNEL_TOKEN=' + token]:
        raise api.ApiError('Actual connector token delivery mismatch')
    if (config.get('Image') != CF_IMAGE or config.get('User') != '65532:65532' or config.get('Cmd') != CF_COMMAND
            or labels.get('com.docker.compose.project') != project
            or labels.get('com.docker.compose.service') != 'cka-lab-tunnel'
            or host.get('ReadonlyRootfs') is not True or host.get('Init') is not True
            or host.get('Privileged') or host.get('CapAdd') or host.get('CapDrop') != ['ALL']
            or host.get('SecurityOpt') not in (['no-new-privileges'], ['no-new-privileges:true'])
            or host.get('Memory') != 128 * 1024**2 or host.get('MemorySwap') != 128 * 1024**2
            or host.get('NanoCpus') != 50000000 or host.get('PidsLimit') != 32
            or host.get('PidMode') or host.get('UTSMode') or host.get('Devices') or host.get('DeviceRequests')
            or host.get('IpcMode', '') not in {'', 'private'} or row.get('Mounts')
            or any(row.get('NetworkSettings', {}).get('Ports', {}).values())
            or set(row.get('NetworkSettings', {}).get('Networks', {})) != {
                'shadowops-cka-lab-staging-origin', 'shadowops-cka-lab-staging-tunnel-egress'}):
        raise api.ApiError('Unsafe actual lab tunnel connector')


def computed_policy(document, pin, *, home=api.HOME_DIR, platform='linux/arm64', test_ca=None, token=None):
    api.compose_policy(document, pin, home=home, platform=platform, test_ca=test_ca)
    item = document['services']['cka-lab-tunnel']
    files = item.get('env_file', [])
    exported_env = item.get('environment') or {}
    # Some installed Compose versions resolve env_file even with the flag.
    # Compare its sole credential privately against the just-read bundle.
    if exported_env and (token is None or exported_env != {'TUNNEL_TOKEN': token}):
        raise api.ApiError('Unexpected exported connector environment')
    if (item.get('image') != CF_IMAGE or item.get('platform') != platform
            or str(item.get('user')) != '65532:65532' or item.get('command') != CF_COMMAND
            or item.get('read_only') is not True or item.get('init') is not True
            or item.get('cap_drop') != ['ALL'] or item.get('security_opt') not in (['no-new-privileges'], ['no-new-privileges:true'])
            or str(item.get('mem_limit')).lower() not in {'128m', '134217728'}
            or str(item.get('memswap_limit')).lower() not in {'128m', '134217728'}
            or float(item.get('cpus', 0)) != 0.05 or item.get('pids_limit') != 32
            or any(item.get(k) for k in ['volumes', 'ports', 'privileged', 'cap_add', 'network_mode', 'pid', 'ipc', 'uts',
                                       'devices', 'entrypoint', 'build', 'secrets', 'configs'])
            or set(item.get('networks', {})) != {'origin', 'tunnel-egress'}
            or document['networks'].get('tunnel-egress', {}).get('name') != 'shadowops-cka-lab-staging-tunnel-egress'
            # Older Compose versions omit env_file from the canonical JSON even
            # with --no-env-resolution. The fixed protected-main definition is
            # executed directly; reject any exported alternate path or inline env.
            or len(files) > 1 or (files and files[0].get('path') != str(home / 'config/tunnel.env'))):
        raise api.ApiError('Unsafe computed lab tunnel connector')


def operate(action):
    account = pwd.getpwnam(api.USER)
    if os.geteuid() != account.pw_uid or account.pw_uid == 0 or account.pw_dir != str(api.HOME_DIR):
        raise api.ApiError('Dedicated lab runtime user required')
    # Reuse the real private API cgroup/auth probe without printing an old
    # private-only publication marker while checking the public connector.
    with contextlib.redirect_stdout(io.StringIO()):
        api.operate('verify')
    pin = api.release(api.decode((api.REPO / 'deploy/cka-lab-staging-release.json').read_bytes()))
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': account.pw_dir,
        'XDG_RUNTIME_DIR': '/run/user/' + str(account.pw_uid),
        'DOCKER_HOST': 'unix:///run/user/' + str(account.pw_uid) + '/cka-lab-docker.sock',
        'CKA_LAB_IMAGE_DIGEST': pin['image_digest']}
    def run(*args, timeout=30):
        result = subprocess.run(list(args), env=env, capture_output=True, text=True, timeout=timeout)
        if result.returncode or len(result.stdout) + len(result.stderr) > 1048576:
            raise api.ApiError('Fixed lab connector command failed')
        return result.stdout.strip()
    command = ['docker', 'compose', '--env-file', '/dev/null', '-p', api.PROJECT,
               '-f', str(api.REPO / 'compose.cka-lab.staging.yaml')]
    if action == 'start':
        value = bundle(api.decode(sys.stdin.read(24577)), pin)
        if run(*command, 'ps', '--all', '--quiet', 'cka-lab-tunnel'):
            raise api.ApiError('Existing connector requires verification, not another initial start')
        api.stage('configure-private-connector')
        api.private_file(api.HOME_DIR / 'config/tunnel.env', 'TUNNEL_TOKEN=' + value['tunnel_token'] + '\n', account.pw_uid)
        api.stage('verify-connector-policy')
        computed_policy(json.loads(run(*command, 'config', '--no-env-resolution', '--format', 'json')), pin, token=value['tunnel_token'])
        api.source_checks(pin)
        api.stage('start-lab-tunnel-only')
        run('docker', 'pull', '--quiet', CF_IMAGE, timeout=180)
        run(*command, 'up', '--detach', '--no-deps', '--pull=never', 'cka-lab-tunnel', timeout=90)
    api.stage('verify-running-connector')
    identifier = run(*command, 'ps', '--quiet', 'cka-lab-tunnel')
    if not re.fullmatch(r'[a-f0-9]{12,64}', identifier):
        raise api.ApiError('Exactly one running connector required')
    # Inspect may contain the connector token in Config.Env; never print it.
    tunnel_policy(json.loads(run('docker', 'inspect', identifier))[0], token=value['tunnel_token'] if action == 'start' else None)
    if action == 'start':
        wait_api(pin, seconds=420)
    else:
        verify_api(pin)
    print('CKA_LAB_TUNNEL_VERIFIED ' + json.dumps({**pin, 'public_endpoint_enabled': True,
        'anonymous_denied': True, 'candidate_acceptance_verified': False}, sort_keys=True))


def main():
    try:
        if (len(sys.argv) != 2 or sys.argv[1] not in {'handoff', 'start', 'verify'}
                or Path(__file__).resolve() != api.REPO / 'scripts/cka_lab_tunnel_runtime.py'):
            return 64
        handoff() if sys.argv[1] == 'handoff' else operate(sys.argv[1])
        return 0
    except Exception:
        print('CKA_LAB_TUNNEL_RUNTIME_BLOCKED stage=' + api.STAGE, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
