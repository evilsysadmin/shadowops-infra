import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import cka_lab_private_api as api

PIN = {'schema': 1, 'source_sha': 'a' * 40, 'image_digest': 'sha256:' + 'b' * 64}
KEYS = {'keys': [{'kty': 'OKP', 'crv': 'Ed25519', 'alg': 'EdDSA', 'use': 'sig', 'kid': 'fixture', 'x': 'A' * 43}]}
CONFIG = {'environment': 'staging', 'access_mode': 'authenticated-staging', 'build': PIN['source_sha'],
          'jwks': KEYS, 'service_credential': 'soc1_' + 'A' * 43}


def controller(home=api.HOME_DIR):
    return {'Config': {'Image': api.IMAGE + PIN['image_digest'], 'User': '0:0', 'Labels': {
        'com.docker.compose.project': api.PROJECT, 'com.docker.compose.service': 'cka-lab'}},
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'],
            'SecurityOpt': ['no-new-privileges:true'], 'Memory': 256 * 1024**2,
            'MemorySwap': 256 * 1024**2, 'NanoCpus': 100000000, 'PidsLimit': 64, 'Init': True,
            'RestartPolicy': {'Name': 'unless-stopped'},
            'Sysctls': {'net.ipv4.ip_forward': '0', 'net.ipv6.conf.all.forwarding': '0'}},
        'NetworkSettings': {'Ports': {'8080/tcp': None}, 'Networks': {name: {} for name in [
            'shadowops-cka-lab-staging-origin', 'shadowops-cka-lab-staging-cluster',
            'shadowops-cka-lab-staging-identity-egress']}},
        'Mounts': [{'Type': 'bind', 'Source': str(home / source), 'Destination': target, 'RW': rw}
            for source, target, rw in [('config/lab.json', '/run/secrets/cka-lab-staging.json', False),
                ('cluster/controller.yaml', '/run/secrets/cka-lab-admin.yaml', False),
                ('controller-state', '/var/lib/cka-lab', True)]]}


def compose():
    row = controller()
    item = {'image': api.IMAGE + PIN['image_digest'], 'platform': 'linux/arm64', 'user': '0:0',
        'read_only': True, 'init': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'pids_limit': 64, 'cpus': 0.1, 'mem_limit': 268435456, 'memswap_limit': 268435456,
        'sysctls': row['HostConfig']['Sysctls'], 'networks': {n: {} for n in ['origin', 'cluster', 'identity-egress']},
        'volumes': [{'type': 'bind', 'source': m['Source'], 'target': m['Destination'], 'read_only': not m['RW']}
                    for m in row['Mounts']]}
    return {'services': {'cka-lab': item, 'cka-lab-tunnel': {}}, 'networks': {
        'origin': {'internal': True, 'name': 'shadowops-cka-lab-staging-origin'},
        'cluster': {'external': True, 'name': 'shadowops-cka-lab-staging-cluster'},
        'identity-egress': {'name': 'shadowops-cka-lab-staging-identity-egress'}}}


class PrivateApiContracts(unittest.TestCase):
    def test_only_explicit_authenticated_configuration_and_immutable_pin(self):
        api.release(PIN)
        api.configuration(CONFIG, PIN)
        for change in [{'environment': 'production'}, {'access_mode': 'pilot'}, {'pilot_subject': 'a'},
                       {'build': 'c' * 40}, {'service_credential': 'browser-token'}, {'identity_ca_pem': 'PRIVATE KEY'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                api.configuration({**CONFIG, **change}, PIN)
        private_key = copy.deepcopy(CONFIG)
        private_key['jwks']['keys'][0]['d'] = 'PRIVATE KEY'
        with self.assertRaises(ValueError):
            api.configuration(private_key, PIN)
        for pin in [{**PIN, 'schema': True}, {**PIN, 'source_sha': 'main'}, {**PIN, 'image_digest': 'latest'}]:
            with self.assertRaises(ValueError):
                api.release(pin)
        with self.assertRaises(ValueError):
            api.decode('{"environment":"staging","environment":"production"}')

    def test_current_source_and_all_four_main_push_checks_are_required(self):
        runs = [{'name': name, 'head_sha': PIN['source_sha'], 'head_branch': 'main', 'event': 'push',
                 'status': 'completed', 'conclusion': 'success', 'repository': {'full_name': api.SOURCE}}
                for name in api.REQUIRED]
        def reader(url):
            return {'sha': PIN['source_sha']} if url.endswith('/commits/main') else {'workflow_runs': runs}
        api.source_checks(PIN, reader)
        with self.assertRaises(ValueError):
            api.source_checks(PIN, lambda url: {'sha': 'c' * 40} if url.endswith('/commits/main') else {'workflow_runs': runs})
        for change in [{'event': 'pull_request'}, {'conclusion': 'failure'}, {'head_sha': 'c' * 40},
                       {'repository': {'full_name': 'another/repo'}}]:
            bad = [{**r, **change} for r in runs]
            with self.subTest(change=change), self.assertRaises(ValueError):
                api.source_checks(PIN, lambda url: {'sha': PIN['source_sha']} if url.endswith('/commits/main') else {'workflow_runs': bad})

    def test_computed_compose_is_checked_before_activation(self):
        good = compose()
        api.compose_policy(good, PIN)
        for key, value in [('ports', ['8080:8080']), ('privileged', True), ('user', '65532'),
                           ('environment', {'CKA_LAB_BUILD_SHA': 'forged'}), ('pid', 'host'),
                           ('mem_limit', 0), ('cpus', 1), ('cap_add', ['NET_ADMIN'])]:
            bad = copy.deepcopy(good)
            bad['services']['cka-lab'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                api.compose_policy(bad, PIN)
        bad = copy.deepcopy(good)
        bad['services']['cka-lab']['volumes'][0]['source'] = '/etc/shadow'
        with self.assertRaises(ValueError):
            api.compose_policy(bad, PIN)

    def test_actual_controller_cannot_escape_limits_mounts_or_networks(self):
        good = controller()
        api.container_policy(good, PIN)
        for key, value in [('Memory', 0), ('MemorySwap', -1), ('NanoCpus', 0), ('PidsLimit', -1),
                           ('Privileged', True), ('PidMode', 'host'), ('IpcMode', 'host'),
                           ('CapAdd', ['SYS_ADMIN']), ('SecurityOpt', ['no-new-privileges:false']), ('Init', False)]:
            bad = copy.deepcopy(good)
            bad['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                api.container_policy(bad, PIN)
        for mutation in [lambda r: r['NetworkSettings']['Ports'].update({'8080/tcp': [{'HostPort': '8080'}]}),
                         lambda r: r['NetworkSettings']['Networks'].update({'host': {}}),
                         lambda r: r['Mounts'][0].update(RW=True),
                         lambda r: r['Mounts'][0].update(Source='/var/run/docker.sock')]:
            bad = copy.deepcopy(good)
            mutation(bad)
            with self.assertRaises(ValueError):
                api.container_policy(bad, PIN)
        extra = copy.deepcopy(good)
        extra['Mounts'].append({'Type': 'bind', 'Source': '/fixture/ca.pem',
                               'Destination': '/opt/runtime/certifi/cacert.pem', 'RW': False})
        with self.assertRaises(ValueError):
            api.container_policy(extra, PIN)
        api.container_policy(extra, PIN, test_ca=Path('/fixture/ca.pem'))

    def test_private_files_never_follow_symlinks_or_replace_foreign_links(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root) / 'private'
            api.private_directory(folder, os.getuid())
            path = folder / 'lab.json'
            api.private_file(path, 'private-config', os.getuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            api.private_file(path, 'next-config', os.getuid())
            target = Path(root) / 'foreign'
            target.write_text('preserve-me')
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                api.private_file(path, 'must-not-write', os.getuid())
            self.assertEqual(target.read_text(), 'preserve-me')
            path.unlink()
            os.link(target, path)
            with self.assertRaises(ValueError):
                api.private_file(path, 'must-not-write', os.getuid())
            self.assertEqual(target.read_text(), 'preserve-me')

    def test_root_handoff_forwards_only_cka_consumer_over_private_stdin(self):
        account = {'environment': 'staging', 'service_credential': CONFIG['service_credential'],
                   'jwks': KEYS, 'identity_ca_pem': 'public account CA, not forwarded', 'build': 'c' * 40}
        def read(path):
            return json.dumps(PIN if path.name.endswith('release.json') else account).encode()
        output = io.StringIO()
        with patch.object(api.os, 'geteuid', return_value=0), \
             patch.object(api, '__file__', str(api.REPO / 'scripts/cka_lab_private_api.py')), \
             patch.object(api, 'root_path'), patch.object(api.Path, 'read_bytes', read), \
             patch.object(api, 'source_checks'), patch.object(api, 'public_json', return_value=KEYS), \
             patch.object(api.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as execute, \
             patch('sys.stdout', output):
            api.handoff()
        args, options = execute.call_args.args[0], execute.call_args.kwargs
        self.assertEqual(args[:3], ['runuser', '--user', api.USER])
        self.assertEqual(args[-1], 'start')
        self.assertEqual(json.loads(options['input']), CONFIG)
        self.assertNotIn(CONFIG['service_credential'], json.dumps(args) + json.dumps(options['env']) + output.getvalue())
        self.assertNotIn('identity_ca_pem', options['input'])

    def test_unprivileged_agent_cannot_read_or_forward_account_secret(self):
        with patch.object(api.os, 'geteuid', return_value=1000), patch.object(api.subprocess, 'run') as execute:
            with self.assertRaises(ValueError):
                api.handoff()
            execute.assert_not_called()

    def test_verification_never_pulls_installs_starts_or_writes(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'home'
            home.mkdir(mode=0o700)
            repo = Path(root) / 'repo'
            (repo / 'deploy').mkdir(parents=True)
            (repo / 'deploy/cka-lab-staging-release.json').write_text(json.dumps(PIN))
            account = SimpleNamespace(pw_uid=os.getuid(), pw_dir=str(home))
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                if args[:2] == ['docker', 'info']: raw = '{}'
                elif args[:2] == ['docker', 'inspect']: raw = json.dumps([controller(home)])
                elif args[:2] == ['docker', 'exec']: raw = 'CKA_LAB_PRIVATE_API_HEALTH_VERIFIED'
                elif args[:2] == ['docker', 'compose'] and args[-3:] == ['ps', '--quiet', 'cka-lab']: raw = 'f' * 64
                else: raise AssertionError('Unexpected mutating command')
                return SimpleNamespace(returncode=0, stdout=raw, stderr='')
            with patch.object(api, 'HOME_DIR', home), patch.object(api, 'REPO', repo), \
                 patch.object(api.pwd, 'getpwnam', return_value=account), \
                 patch.object(api, 'verify_daemon'), patch.object(api, 'verify_cluster'), \
                 patch.object(api, 'private_directory', side_effect=AssertionError('write')), \
                 patch.object(api, 'private_file', side_effect=AssertionError('write')), \
                 patch.object(api, 'source_checks', side_effect=AssertionError('network lookup')), \
                 patch.object(api.subprocess, 'run', side_effect=command), patch('builtins.print'):
                api.operate('verify')
            self.assertEqual(len(calls), 4)


if __name__ == '__main__':
    unittest.main()
