#!/usr/bin/env python3
"""Own only the independent CKA staging account tunnel, DNS and narrow Vault secret."""
import base64
import json
import os
import ssl
import urllib.parse
import urllib.request
from chronicles_api_provision import Cloudflare, ProvisionError, UUID_RE, resolve_vault
from oci_control_plane import config_from_env, resolve_existing_host
from identity_staging_provision import load_existing
from cka_account_contract import HOST, SECRET, validate, public_keys

NAME='cka-account-staging'
ZONE='shadowops.dpdns.org'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None

def read_keys():
    url='https://id-staging.shadowops.dpdns.org/api/identity/jwks'
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(urllib.request.Request(url,headers={'Accept':'application/json'}),timeout=5) as response:
        raw=response.read(16385)
        if response.status!=200 or response.geturl()!=url or len(raw)>16384:
            raise ProvisionError('Identity public trust anchor unavailable')
        keys=json.loads(raw)
    public_keys(keys);return keys

def desired_ingress():
    return {'config':{'ingress':[
        {'hostname':HOST,'service':'http://cka-account:8080','originRequest':{'httpHostHeader':HOST,'connectTimeout':10}},
        {'service':'http_status:404'}]}}

def provision(sdk,env,cf,keys_reader=read_keys):
    config=config_from_env(sdk,env);compartment,_=resolve_existing_host(sdk,config)
    vault,key,_=resolve_vault(sdk,config,compartment)
    identity=load_existing(sdk,config,vault,compartment)
    if identity is None or 'cka-simulator' not in identity['consumers']:
        raise ProvisionError('CKA consumer must be explicitly registered first')
    keys=keys_reader();public_keys(keys)
    rows=cf.call('GET',f'/accounts/{cf.account}/cfd_tunnel?'+urllib.parse.urlencode({'name':NAME,'is_deleted':'false'})) or []
    rows=[r for r in rows if r.get('name')==NAME]
    if len(rows)>1:raise ProvisionError('Ambiguous CKA account tunnel')
    tunnel=rows[0] if rows else None
    if tunnel and (tunnel.get('config_src')!='cloudflare' or not UUID_RE.fullmatch(tunnel.get('id',''))):raise ProvisionError('CKA tunnel ownership mismatch')
    zones=cf.call('GET','/zones?'+urllib.parse.urlencode({'name':ZONE,'account.id':cf.account}))
    if not isinstance(zones,list) or len(zones)!=1:raise ProvisionError('Ambiguous CKA account DNS zone')
    zone=zones[0]['id']
    dns=cf.call('GET',f'/zones/{zone}/dns_records?'+urllib.parse.urlencode({'name':HOST})) or []
    target=tunnel['id']+'.cfargotunnel.com' if tunnel else None
    if len(dns)>1 or (dns and (target is None or dns[0].get('type')!='CNAME' or dns[0].get('content')!=target or dns[0].get('proxied') is not True)):
        raise ProvisionError('CKA account hostname belongs to another owner')
    client=sdk.vault.VaultsClient(config)
    secret_rows=sdk.pagination.list_call_get_all_results(client.list_secrets,compartment,vault_id=vault,name=SECRET).data
    if len(secret_rows)>1 or (secret_rows and str(secret_rows[0].lifecycle_state).upper()!='ACTIVE'):raise ProvisionError('CKA account custody requires review')
    if tunnel is None:
        tunnel=cf.call('POST',f'/accounts/{cf.account}/cfd_tunnel',{'name':NAME,'config_src':'cloudflare'})
        if tunnel.get('config_src')!='cloudflare' or not UUID_RE.fullmatch(tunnel.get('id','')):raise ProvisionError('Invalid created CKA tunnel')
        target=tunnel['id']+'.cfargotunnel.com'
    token=cf.call('GET',f'/accounts/{cf.account}/cfd_tunnel/{tunnel["id"]}/token')
    bundle={'schema':1,'environment':'staging','service_credential':identity['consumers']['cka-simulator'],'jwks':keys,'identity_ca_pem':identity['ca_certificate_pem'],'tunnel_token':token}
    validate(bundle)
    content=sdk.vault.models.Base64SecretContentDetails(content_type='BASE64',stage='CURRENT',content=base64.b64encode(json.dumps(bundle).encode()).decode())
    ops=sdk.vault.VaultsClientCompositeOperations(client)
    wait={'wait_for_states':['ACTIVE'],'waiter_kwargs':{'max_interval_seconds':5,'max_wait_seconds':300}}
    if secret_rows:
        ops.update_secret_and_wait_for_state(secret_rows[0].id,sdk.vault.models.UpdateSecretDetails(secret_content=content),**wait)
    else:
        ops.create_secret_and_wait_for_state(sdk.vault.models.CreateSecretDetails(compartment_id=compartment,vault_id=vault,key_id=key,secret_name=SECRET,
            description='Independent CKA staging account verifier only; no lab or Identity signing material',
            freeform_tags={'application':'cka-account','environment':'staging','managed-by':'shadowops-infra'},secret_content=content),**wait)
    cf.call('PUT',f'/accounts/{cf.account}/cfd_tunnel/{tunnel["id"]}/configurations',desired_ingress())
    if not dns:cf.call('POST',f'/zones/{zone}/dns_records',{'type':'CNAME','name':HOST,'content':target,'proxied':True,'comment':'Isolated CKA account staging, managed by shadowops-infra'})
    return 'CKA_ACCOUNT_STAGING_PROVISIONED custody=independent'

def main():
    try:
        import oci
        print(provision(oci,os.environ,Cloudflare(os.environ)));return 0
    except Exception as error:
        print('CKA_ACCOUNT_PROVISION_BLOCKED type='+type(error).__name__);return 1
if __name__=='__main__':raise SystemExit(main())
