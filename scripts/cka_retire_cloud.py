#!/usr/bin/env python3
"""Exact CKA cloud retirement. Keeps the repo, shared Identity/Vault/key/A1."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
from urllib.parse import urlencode
from chronicles_api_provision import Cloudflare, ProvisionError, resolve_vault
from oci_control_plane import config_from_env, resolve_existing_host
from identity_staging_provision import load_existing, SECRET_NAME
from identity_staging_bundle import validate

ZONE='shadowops.dpdns.org'
PAGES={'cka-simulator':'cka.shadowops.dpdns.org','cka-account-staging':'staging.cka.shadowops.dpdns.org'}
TUNNELS={'cka-account-staging':('cka-api-staging.shadowops.dpdns.org','http://cka-account:8080'),
         'cka-lab-staging':('cka-labs-staging.shadowops.dpdns.org','http://cka-lab:8080')}
SECRETS={'cka-account-staging-runtime':'cka-account','cka-lab-staging-tunnel':'cka-lab-staging'}
UUID=re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')

def list_cf(cf,path,**query):
    values=[]
    for page in range(1,21):
        rows=cf.call('GET',path+'?'+urlencode({**query,'per_page':100,'page':page}))
        if not isinstance(rows,list):raise ProvisionError('Complete Cloudflare inventory required')
        values.extend(rows)
        if len(rows)<100:return values
    raise ProvisionError('Cloudflare inventory too large')

def cloud_plan(cf):
    if not re.fullmatch(r'[a-f0-9]{32}',cf.account):raise ProvisionError('Fixed Cloudflare account required')
    zones=cf.call('GET','/zones?'+urlencode({'name':ZONE,'account.id':cf.account}))
    if len(zones)!=1 or zones[0].get('name')!=ZONE:raise ProvisionError('Exact zone required')
    zone=zones[0]['id']
    if not re.fullmatch(r'[a-f0-9]{32}',zone):raise ProvisionError('Invalid zone')
    projects=list_cf(cf,f'/accounts/{cf.account}/pages/projects')
    tunnels=list_cf(cf,f'/accounts/{cf.account}/cfd_tunnel',is_deleted='false')
    owned_projects=[];owned_tunnels=[];dns=[]
    for name,host in PAGES.items():
        rows=[p for p in projects if p.get('name')==name]
        if len(rows)>1:raise ProvisionError('Duplicate CKA Pages project')
        if rows:
            p=cf.call('GET',f'/accounts/{cf.account}/pages/projects/{name}')
            if p.get('name')!=name or p.get('subdomain')!=name+'.pages.dev':raise ProvisionError('Foreign Pages project')
            domains=p.get('domains',[])
            if not isinstance(domains,list) or set(domains)-{host,name+'.pages.dev'}:raise ProvisionError('Pages project has foreign domain')
            owned_projects.append((name,host,host in domains))
        records=list_cf(cf,f'/zones/{zone}/dns_records',name=host)
        if len(records)>1 or any(d.get('name')!=host or d.get('type')!='CNAME' or d.get('content')!=name+'.pages.dev' for d in records):
            raise ProvisionError('Foreign CKA Pages DNS')
        dns.extend(records)
    for name,(host,service) in TUNNELS.items():
        rows=[t for t in tunnels if t.get('name')==name]
        if len(rows)>1:raise ProvisionError('Duplicate CKA tunnel')
        tunnel=rows[0] if rows else None
        if tunnel:
            identity=tunnel.get('id','')
            if not UUID.fullmatch(identity) or tunnel.get('config_src')!='cloudflare':raise ProvisionError('Foreign CKA tunnel')
            config=cf.call('GET',f'/accounts/{cf.account}/cfd_tunnel/{identity}/configurations')
            ingress=config.get('config',{}).get('ingress')
            if ingress!=[{'service':'http_status:404'}]:
                if (not isinstance(ingress,list) or len(ingress)!=2 or ingress[-1]!={'service':'http_status:404'}
                        or ingress[0].get('hostname')!=host or ingress[0].get('service')!=service):
                    raise ProvisionError('Tunnel has foreign ingress')
            owned_tunnels.append((name,identity))
        records=list_cf(cf,f'/zones/{zone}/dns_records',name=host)
        if len(records)>1 or any(tunnel is None or d.get('name')!=host or d.get('type')!='CNAME' or d.get('content')!=tunnel['id']+'.cfargotunnel.com' for d in records):
            raise ProvisionError('Foreign CKA tunnel DNS')
        dns.extend(records)
    for record in dns:
        if not re.fullmatch(r'[a-f0-9]{32}',record.get('id','')):raise ProvisionError('Invalid DNS identity')
    return {'zone':zone,'dns':dns,'projects':owned_projects,'tunnels':owned_tunnels}

def remove_consumer(bundle):
    validate(bundle)
    updated=copy.deepcopy(bundle)
    updated['consumers'].pop('cka-simulator',None)
    validate(updated)
    # Every other secret/key/account credential is unchanged byte for byte.
    assert {k:v for k,v in bundle.items() if k!='consumers'}=={k:v for k,v in updated.items() if k!='consumers'}
    assert {k:v for k,v in bundle['consumers'].items() if k!='cka-simulator'}==updated['consumers']
    return updated

def vault_plan(sdk,env):
    config=config_from_env(sdk,env);compartment,_=resolve_existing_host(sdk,config)
    vault,key,_=resolve_vault(sdk,config,compartment)
    client=sdk.vault.VaultsClient(config)
    rows=sdk.pagination.list_call_get_all_results(client.list_secrets,compartment,vault_id=vault).data
    selected=[]
    for name,application in SECRETS.items():
        own=[s for s in rows if s.secret_name==name and s.lifecycle_state!='DELETED']
        if len(own)>1:raise ProvisionError('Duplicate CKA secret')
        if own:
            response=client.get_secret(own[0].id);meta=response.data
            if (meta.vault_id!=vault or meta.key_id!=key or meta.freeform_tags!={'application':application,'environment':'staging','managed-by':'shadowops-infra'}
                    or meta.lifecycle_state not in {'ACTIVE','PENDING_DELETION'}):raise ProvisionError('Foreign CKA secret')
            selected.append((name,meta.id,meta.lifecycle_state,response.headers['etag']))
    own=[s for s in rows if s.secret_name==SECRET_NAME and s.lifecycle_state!='DELETED']
    if len(own)!=1 or own[0].lifecycle_state!='ACTIVE':raise ProvisionError('Shared Identity custody must exist')
    before=client.get_secret(own[0].id)
    bundle=load_existing(sdk,config,vault,compartment)
    after=client.get_secret(own[0].id)
    if before.headers['etag']!=after.headers['etag']:raise ProvisionError('Identity custody changed; retry')
    updated=remove_consumer(bundle)
    return client,selected,(own[0].id,after.headers['etag'],bundle,updated)

def retire_cloud(cf,plan,*,purge=True):
    # Withdraw origins first, even if a later deletion needs an operator retry.
    for name,identity in plan['tunnels']:
        cf.call('PUT',f'/accounts/{cf.account}/cfd_tunnel/{identity}/configurations',{'config':{'ingress':[{'service':'http_status:404'}]}})
    for record in plan['dns']:cf.call('DELETE',f'/zones/{plan["zone"]}/dns_records/{record["id"]}')
    for name,host,custom in plan['projects']:
        if custom:cf.call('DELETE',f'/accounts/{cf.account}/pages/projects/{name}/domains/{host}')
        # Project deletion also deletes all of its production and preview deployments.
        cf.call('DELETE',f'/accounts/{cf.account}/pages/projects/{name}')
    if not purge:return
    for name,identity in plan['tunnels']:
        # Cloudflare requires no live connectors. Stop them with make cka-retire-host.
        connections=cf.call('GET',f'/accounts/{cf.account}/cfd_tunnel/{identity}/connections')
        if connections:raise ProvisionError('CKA connector still running; run make cka-retire-host then retry')
        cf.call('DELETE',f'/accounts/{cf.account}/cfd_tunnel/{identity}')

def execute(sdk,env,cf,*,mutate=False,purge=True):
    plan=cloud_plan(cf)
    client,secrets,identity=vault_plan(sdk,env)
    report={'dns':len(plan['dns']),'pages':len(plan['projects']),'tunnels':len(plan['tunnels']),
            'dedicated_secrets':len(secrets),'shared_identity_cka_consumer':'cka-simulator' in identity[2]['consumers']}
    print('CKA_RETIRE_CLOUD_PLAN '+json.dumps(report,sort_keys=True),flush=True)
    if not mutate:return
    retire_cloud(cf,plan,purge=purge)
    sid,etag,before,after=identity
    if before!=after:
        content=sdk.vault.models.Base64SecretContentDetails(content_type='BASE64',stage='CURRENT',
                    content=base64.b64encode(json.dumps(after).encode()).decode())
        client.update_secret(sid,sdk.vault.models.UpdateSecretDetails(secret_content=content),if_match=etag)
    for name,sid,state,etag in secrets:
        if state=='ACTIVE':
            client.schedule_secret_deletion(sid,sdk.vault.models.ScheduleSecretDeletionDetails(
                time_of_deletion=datetime.now(timezone.utc)+timedelta(days=2)),if_match=etag)
    verify=cloud_plan(cf)
    if any(verify[k] for k in (('dns','projects','tunnels') if purge else ('dns','projects'))):raise ProvisionError('CKA cloud resources remain')
    for name,sid,state,etag in secrets:
        if client.get_secret(sid).data.lifecycle_state not in {'PENDING_DELETION','DELETED'}:
            raise ProvisionError('CKA secret deletion is not scheduled')
    print('CKA_RETIRE_CLOUD_VERIFIED dns=0 pages=0 tunnels=0 dedicated_secrets=pending_deletion shared_identity=preserved' if purge else 'CKA_RETIRE_PUBLIC_WITHDRAWN dns=0 pages=0 origins=404 host_cleanup=pending tunnels='+str(len(verify['tunnels'])))

if __name__=='__main__':
    try:
        import oci
        if sys.argv[1:] not in (['plan'],['withdraw'],['retire']):raise ProvisionError('Use plan|retire')
        execute(oci,os.environ,Cloudflare(os.environ),mutate=sys.argv[1]!='plan',purge=sys.argv[1]=='retire')
    except Exception as error:
        # No config, bundle, bearer, tunnel token or SDK response in logs.
        print('CKA_RETIRE_CLOUD_BLOCKED '+(str(error) if isinstance(error,ProvisionError) else 'type='+type(error).__name__),file=sys.stderr)
        raise SystemExit(1)
