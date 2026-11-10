"""Strict, staging-only validation of normalized Atlas Compose policy.

This is a pure admission check; it never deploys, reads credentials or opens
network connections. The host must additionally verify image provenance,
network ownership, backup/restore and the separately provisioned configuration.
"""
import re

IMAGE = 'ghcr.io/evilsysadmin/shadowops-identity@'
TUNNEL = 'cloudflare/cloudflared@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4'
PROJECT = 'shadowops-identity-staging'
LEGACY_CONFIG = '/etc/shadowops/identity-staging/atlas-service.json'
SNOOKER_CONFIG = '/etc/shadowops/identity-staging/atlas-snooker-service.json'
ALLOWED_CONFIGS = frozenset({LEGACY_CONFIG, SNOOKER_CONFIG})

class AtlasPolicyError(ValueError):
    pass


def validate_atlas_compose(config, digest, config_source=LEGACY_CONFIG):
    def fail():
        raise AtlasPolicyError('Unsafe Atlas staging policy')
    if (not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
            or config_source not in ALLOWED_CONFIGS):
        fail()
    if not isinstance(config, dict) or config.get('name') != PROJECT or set(config.get('services', {})) != {'identity', 'identity-tunnel'}:
        fail()
    if config.get('volumes') or config.get('secrets') or config.get('configs'):
        fail()
    networks = config.get('networks', {})
    if set(networks) != {'origin', 'atlas-egress', 'tunnel-egress'}:
        fail()
    for name, internal in [('origin', True), ('atlas-egress', False), ('tunnel-egress', False)]:
        network = networks[name]
        if not isinstance(network, dict) or network.get('name') != PROJECT + '-' + name or bool(network.get('internal', False)) != internal:
            fail()
        if set(network) - {'name','ipam','internal'} or network.get('ipam') not in (None, {}):
            fail()
    allowed = {'cap_drop','cpus','command','entrypoint','image','init','mem_limit','networks',
               'pids_limit','platform','read_only','restart','security_opt','user','volumes'}
    for name, svc in config['services'].items():
        if not isinstance(svc, dict):
            fail()
        permitted = allowed | ({'depends_on','environment'} if name == 'identity-tunnel' else set())
        if set(svc) - permitted:
            fail()
        image = IMAGE + digest if name == 'identity' else TUNNEL
        if (svc.get('image') != image or svc.get('platform') != 'linux/arm64' or svc.get('user') != '65532:65532'
                or svc.get('read_only') is not True or svc.get('init') is not True
                or svc.get('cap_drop') != ['ALL'] or svc.get('security_opt') != ['no-new-privileges:true']
                or svc.get('entrypoint') is not None or svc.get('restart') != 'unless-stopped'
                or svc.get('pids_limit') != (128 if name == 'identity' else 64)
                or str(svc.get('mem_limit')) != ('268435456' if name == 'identity' else '134217728')
                or svc.get('cpus') != (0.75 if name == 'identity' else 0.25)):
            fail()
        expected_networks = {'origin','atlas-egress'} if name == 'identity' else {'origin','tunnel-egress'}
        if set(svc.get('networks', {})) != expected_networks:
            fail()
        if name == 'identity':
            if svc['networks']['origin'] != {'aliases': ['id-staging.shadowops.dpdns.org']} or svc['networks']['atlas-egress'] not in ({}, None):
                fail()
        elif any(item not in ({}, None) for item in svc['networks'].values()):
            fail()
        expected_mount = (config_source,'/run/secrets/identity-staging.json') if name == 'identity' else ('/etc/shadowops/identity-staging/ca.pem','/run/identity/ca.pem')
        mounts = svc.get('volumes')
        if (not isinstance(mounts, list) or len(mounts) != 1 or mounts[0].get('type') != 'bind'
                or mounts[0].get('source') != expected_mount[0] or mounts[0].get('target') != expected_mount[1]
                or mounts[0].get('read_only') is not True or set(mounts[0]) - {'type','source','target','read_only','bind'}
                or mounts[0].get('bind') not in (None, {'create_host_path': True})):
            fail()
        if name == 'identity':
            if svc.get('command') is not None:
                fail()
        else:
            if (svc.get('command') != ['tunnel','--no-autoupdate','--metrics','127.0.0.1:20241','run']
                    or set(svc.get('environment', {})) != {'TUNNEL_TOKEN'}
                    or svc.get('depends_on', {}).get('identity', {}).get('condition') != 'service_healthy'
                    or set(svc.get('depends_on', {})) != {'identity'}):
                fail()
