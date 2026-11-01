import base64
import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import cka_lab_public as public
import cka_lab_tunnel as contract
import cka_lab_tunnel_provision as provision
import cka_lab_tunnel_runtime as runtime
from cka_lab_private_api import ApiError, HOST, ORIGIN
from test_cka_lab_private_api import PIN
from test_cka_lab_private_api import compose

ID = '11111111-1111-4111-8111-111111111111'
VAULT = 'ocid1.vault.oc1.eu-frankfurt-1.syntheticvault123456789'
TOKEN = 'synthetic-tunnel-token-' + 'A' * 48
BUNDLE = {**PIN, 'environment': 'staging', 'hostname': HOST, 'account_id': 'a' * 32,
          'tunnel_id': ID, 'tunnel_token': TOKEN}


def location():
    return {**PIN, 'environment': 'staging', 'hostname': HOST, 'vault_id': VAULT,
            'tunnel_id': ID, 'created_at': datetime.now(timezone.utc).isoformat()}


class Cloudflare:
    account = 'a' * 32
    def __init__(self, *, existing=False, foreign_dns=False, count=0, foreign_ingress=False):
        self.calls = []
        self.existing, self.foreign_dns, self.count, self.foreign_ingress = existing, foreign_dns, count, foreign_ingress
    def call(self, method, path, data=None):
        self.calls.append((method, path, data))
        tunnel = {'id': ID, 'name': contract.NAME, 'config_src': 'cloudflare'}
        if method == 'GET' and '/cfd_tunnel?' in path:
            from urllib.parse import parse_qs, urlsplit
            page = int(parse_qs(urlsplit(path).query)['page'][0])
            values = [tunnel] if self.existing else [{'name': 'other-' + str(n)} for n in range(self.count)]
            return values[(page-1)*100:page*100]
        if path.startswith('/zones?'): return [{'id': 'zone', 'name': contract.ZONE}]
        if method == 'GET' and '/dns_records?' in path:
            return [{'name': HOST, 'type': 'CNAME', 'content': 'foreign.pages.dev', 'proxied': True}] if self.foreign_dns else []
        if method == 'GET' and path.endswith('/configurations'):
            return {'config': {'ingress': [{'service': 'ssh://another-service:22'}]}} if self.foreign_ingress else provision.desired_ingress()
        if method == 'POST' and path.endswith('/cfd_tunnel'): return tunnel
        if method == 'GET' and path.endswith('/token'): return TOKEN
        if method in {'POST', 'PUT'}: return {}
        raise AssertionError('Unexpected Cloudflare operation')


class CloudFixture:
    def __init__(self, *, count=0, existing=False, state='ACTIVE', tags=None, vault_type='DEFAULT'):
        self.writes = []
        own = NS(id='own-secret', lifecycle_state=state)
        values = [NS(id='secret-' + str(n), lifecycle_state='ACTIVE') for n in range(count)]
        if existing: values.append(own)
        def list_secrets(compartment, **kwargs):
            if 'name' in kwargs: return [own] if existing else []
            return values if compartment == 'target' else []
        client = NS(list_secrets=list_secrets,
                    get_secret=lambda _: NS(data=NS(key_id='key', vault_id=VAULT, freeform_tags=contract.TAGS if tags is None else tags)))
        def model(**kwargs): return NS(**kwargs)
        ops = NS(create_secret_and_wait_for_state=lambda data, **kwargs: self.writes.append(('create', data)),
                 update_secret_and_wait_for_state=lambda key, data, **kwargs: self.writes.append(('update', data)))
        identity = NS(list_region_subscriptions=lambda _: [NS(region_name='eu-frankfurt-1', is_home_region=True, status='READY')],
                      list_compartments=lambda *args, **kwargs: [NS(id='target', lifecycle_state='ACTIVE')])
        self.sdk = NS(identity=NS(IdentityClient=lambda config: identity),
            vault=NS(VaultsClient=lambda config: client, VaultsClientCompositeOperations=lambda _: ops,
                     models=NS(Base64SecretContentDetails=model, UpdateSecretDetails=model, CreateSecretDetails=model)),
            key_management=NS(KmsVaultClient=lambda _: NS(get_vault=lambda _: NS(data=NS(vault_type=vault_type)))),
            secrets=NS(SecretsClient=lambda _: NS(get_secret_bundle_by_name=lambda **kwargs:
                NS(data=NS(secret_bundle_content=NS(content=base64.b64encode(json.dumps(BUNDLE).encode()).decode()))))),
            pagination=NS(list_call_get_all_results=lambda fn,*args,**kwargs:NS(data=fn(*args,**kwargs))))
    def run(self, cf):
        config = {'tenancy': 'tenancy', 'region': 'eu-frankfurt-1'}
        with patch.object(provision, 'config_from_env', return_value=config), \
             patch.object(provision, 'resolve_existing_host', return_value=('target', 'host')), \
             patch.object(provision, 'resolve_vault', return_value=(VAULT, 'key', 'target')):
            return provision.provision(self.sdk, {}, cf, PIN)


class PublicationContracts(unittest.TestCase):
    def test_tunnel_computed_and_actual_policy_reject_privilege_mount_or_route_changes(self):
        document = compose()
        document['networks']['tunnel-egress'] = {'name': 'shadowops-cka-lab-staging-tunnel-egress'}
        item = {'image': contract.CF_IMAGE, 'platform': 'linux/arm64', 'user': '65532:65532',
            'command': contract.CF_COMMAND, 'read_only': True, 'init': True, 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'mem_limit': 134217728, 'memswap_limit': 134217728,
            'cpus': 0.05, 'pids_limit': 32, 'networks': {'origin': {}, 'tunnel-egress': {}},
            'env_file': [{'path': str(runtime.api.HOME_DIR / 'config/tunnel.env'), 'required': True}]}
        document['services']['cka-lab-tunnel'] = item
        runtime.computed_policy(document, PIN)
        # Actual runner Compose omits unresolved env_file in its JSON export.
        legacy = copy.deepcopy(document)
        del legacy['services']['cka-lab-tunnel']['env_file']
        runtime.computed_policy(legacy, PIN)
        resolved = copy.deepcopy(legacy)
        resolved['services']['cka-lab-tunnel']['environment'] = {'TUNNEL_TOKEN': TOKEN}
        runtime.computed_policy(resolved, PIN, token=TOKEN)
        with self.assertRaises(ApiError): runtime.computed_policy(resolved, PIN)
        with self.assertRaises(ApiError): runtime.computed_policy(resolved, PIN, token='wrong-token')
        resolved['services']['cka-lab-tunnel']['environment']['OTHER_SECRET'] = 'forbidden'
        with self.assertRaises(ApiError): runtime.computed_policy(resolved, PIN, token=TOKEN)
        wrong_path = copy.deepcopy(document)
        wrong_path['services']['cka-lab-tunnel']['env_file'][0]['path'] = '/etc/other-secret'
        with self.assertRaises(ApiError): runtime.computed_policy(wrong_path, PIN)
        for key, value in [('ports', ['8080:8080']), ('volumes', ['/var/run/docker.sock:/socket']),
                           ('environment', {'TUNNEL_TOKEN': 'inline-token'}), ('cpus', 1), ('user', '0:0')]:
            bad = copy.deepcopy(document)
            bad['services']['cka-lab-tunnel'][key] = value
            with self.subTest(key=key), self.assertRaises(ApiError): runtime.computed_policy(bad, PIN)
        actual = {'Config': {'Image': contract.CF_IMAGE, 'User': '65532:65532', 'Cmd': contract.CF_COMMAND,
            'Labels': {'com.docker.compose.project': runtime.api.PROJECT, 'com.docker.compose.service': 'cka-lab-tunnel'}},
            'HostConfig': {'ReadonlyRootfs': True, 'Init': True, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'],
                'Memory': 134217728, 'MemorySwap': 134217728, 'NanoCpus': 50000000, 'PidsLimit': 32},
            'NetworkSettings': {'Ports': {}, 'Networks': {'shadowops-cka-lab-staging-origin': {},
                                                       'shadowops-cka-lab-staging-tunnel-egress': {}}}, 'Mounts': []}
        runtime.tunnel_policy(actual)
        with self.assertRaises(ApiError): runtime.tunnel_policy(actual, token=TOKEN)
        actual['Config']['Env'] = ['PATH=/bin', 'TUNNEL_TOKEN=' + TOKEN]
        runtime.tunnel_policy(actual, token=TOKEN)
        with self.assertRaises(ApiError): runtime.tunnel_policy(actual, token='wrong-token')
        for change in [lambda x:x['HostConfig'].update(Privileged=True),
                       lambda x:x['Mounts'].append({'Source': '/secret'}),
                       lambda x:x['NetworkSettings']['Networks'].update({'shadowops-cka-lab-staging-cluster': {}})]:
            bad = copy.deepcopy(actual)
            change(bad)
            with self.assertRaises(ApiError): runtime.tunnel_policy(bad)

    def test_publication_workflow_orders_readiness_and_keeps_cloud_secrets_out_of_build(self):
        text = (ROOT / '.github/workflows/cka-lab-publish.yml').read_text()
        self.assertIn('workflow_dispatch:', text)
        self.assertNotIn('  push:', text)
        browser = text.split('  publish-browser:', 1)[1]
        self.assertLess(browser.index('cka_lab_public.py wait-api'), browser.index('npm run build:lab-staging'))
        self.assertLess(browser.index('cka_lab_public.py api'), browser.index('wrangler@'))
        build = browser.split('- name: Build the authenticated lab frontend', 1)[1].split('- name: Recheck public API', 1)[0]
        for secret in ['CLOUDFLARE_API_TOKEN', 'OCI_PRIVATE_KEY', 'service_credential', 'TUNNEL_TOKEN']:
            self.assertNotIn(secret, build)
        self.assertIn('--project-name cka-account-staging', browser)
        self.assertIn("'candidate_acceptance_verified':False", browser)

    def test_new_resources_have_isolated_custody_without_identity_credentials(self):
        fixture, cf = CloudFixture(count=149), Cloudflare()
        value = fixture.run(cf)
        self.assertNotIn('tunnel_token', value)
        self.assertEqual(value['vault_id'], VAULT)
        self.assertEqual(len(fixture.writes), 1)
        kind, details = fixture.writes[0]
        self.assertEqual(kind, 'create')
        self.assertEqual(details.secret_name, contract.SECRET)
        self.assertEqual(details.freeform_tags, contract.TAGS)
        stored = json.loads(base64.b64decode(details.secret_content.content))
        self.assertEqual(stored, BUNDLE)
        self.assertTrue(all('chronicles' not in path and 'chess-studio' not in path for _, path, _ in cf.calls))
        self.assertTrue(any(method == 'PUT' and data == provision.desired_ingress() for method, _, data in cf.calls))

    def test_budget_permission_custody_or_dns_fail_before_any_mutation(self):
        cases = [(CloudFixture(count=150), Cloudflare()),
                 (CloudFixture(), Cloudflare(count=1000)),
                 (CloudFixture(), Cloudflare(foreign_dns=True)),
                 (CloudFixture(existing=True, tags={'application': 'other'}), Cloudflare(existing=True)),
                 (CloudFixture(existing=True, state='PENDING_DELETION'), Cloudflare(existing=True)),
                 (CloudFixture(vault_type='VIRTUAL_PRIVATE'), Cloudflare()),
                 (CloudFixture(existing=True), Cloudflare(existing=True, foreign_ingress=True))]
        for fixture, cf in cases:
            with self.subTest(count=len(cf.calls)), self.assertRaises(Exception): fixture.run(cf)
            self.assertEqual(fixture.writes, [])
            self.assertTrue(all(method == 'GET' for method, _, _ in cf.calls))
        fixture, cf = CloudFixture(), Cloudflare()
        with patch.object(provision, 'free_secret_inventory', side_effect=PermissionError('no inventory')):
            with self.assertRaises(PermissionError): fixture.run(cf)
        self.assertEqual(cf.calls, [])
        self.assertEqual(fixture.writes, [])

    def test_same_owned_bundle_is_not_rotated_on_retry(self):
        fixture, cf = CloudFixture(existing=True), Cloudflare(existing=True)
        fixture.run(cf)
        self.assertEqual(fixture.writes, [])
        self.assertFalse(any(method == 'POST' and path.endswith('/cfd_tunnel') for method, path, _ in cf.calls))

    def test_locator_staging_never_contains_a_token_and_reader_refuses_links(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'locator.json'
            value = location()
            with patch.object(provision, 'LOCATOR', str(path)):
                command = provision.locator_command(value)
            self.assertNotIn(TOKEN, command)
            self.assertNotIn('tunnel_token', command)
            result = subprocess.run(['bash', '-s'], input=command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'CKA_LAB_TUNNEL_LOCATOR_STAGED')
            self.assertNotIn(VAULT, result.stdout)
            with patch.object(runtime, 'LOCATOR', str(path)), patch.object(runtime.pwd, 'getpwnam', return_value=NS(pw_uid=os.getuid())):
                self.assertEqual(runtime.read_locator(PIN), value)
                path.chmod(0o644)
                with self.assertRaises(ApiError): runtime.read_locator(PIN)
                path.chmod(0o600)
                other = Path(root) / 'other'
                path.rename(other)
                path.symlink_to(other)
                with self.assertRaises(OSError): runtime.read_locator(PIN)

    def test_bundle_and_locator_are_fixed_staging_and_fresh(self):
        contract.bundle(BUNDLE, PIN)
        for change in [{'environment': 'production'}, {'hostname': 'other.example'}, {'tunnel_token': "bad'\n"},
                       {'service_credential': 'must-not-copy'}, {'source_sha': 'c' * 40}]:
            with self.assertRaises(ValueError): contract.bundle({**BUNDLE, **change}, PIN)
        old = {**location(), 'created_at': (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()}
        with self.assertRaises(ValueError): contract.locator(old, PIN)

    def test_public_verification_requires_current_release_and_anonymous_denial(self):
        expected = {'application': 'cka-exam-simulator', 'build': PIN['source_sha'], 'mode': 'restricted-lab-pilot'}
        def responder(url, **kwargs):
            headers = {'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': ORIGIN}
            if url.endswith('/release'): return 200, json.dumps(expected).encode(), headers
            if url.endswith('/readyz'): return 200, b'{"status":"ok"}', headers
            self.assertEqual(kwargs, {'body': b'{}', 'origin': ORIGIN})
            return 401, b'', headers
        with patch.object(public, 'request', side_effect=responder): public.verify_api(PIN)
        for status in [200, 302, 403, 503]:
            def invalid(url, **kwargs):
                return (status, b'', {}) if url.endswith('/capabilities') else responder(url, **kwargs)
            with self.subTest(status=status), patch.object(public, 'request', side_effect=invalid):
                with self.assertRaises(ValueError): public.verify_api(PIN)
        expected['build'] = 'c' * 40
        with patch.object(public, 'request', side_effect=responder):
            with self.assertRaises(ValueError): public.verify_api(PIN)

    def test_root_token_handoff_uses_private_stdin_not_argv_env_or_logs(self):
        output = io.StringIO()
        with patch.object(runtime.os, 'geteuid', return_value=0), \
             patch.object(runtime.api.Path, 'read_bytes', return_value=json.dumps(PIN).encode()), \
             patch.object(runtime.api, 'source_checks'), patch.object(runtime, 'read_locator', return_value=location()), \
             patch.object(runtime, 'read_bundle', return_value=BUNDLE), \
             patch.object(runtime.subprocess, 'run', return_value=NS(returncode=0)) as execute, patch('sys.stdout', output):
            runtime.handoff()
        args, values = execute.call_args.args[0], execute.call_args.kwargs
        self.assertEqual(args[:3], ['runuser', '--user', runtime.api.USER])
        self.assertEqual(json.loads(values['input']), BUNDLE)
        self.assertNotIn(TOKEN, json.dumps(args) + json.dumps(values['env']) + output.getvalue())
        self.assertNotIn('signing', values['input'])


if __name__ == '__main__': unittest.main()
