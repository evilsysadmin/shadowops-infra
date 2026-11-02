#!/usr/bin/env python3
"""Deliver only Football's existing IdP service proof to its Pages edge binding."""
import os
import sys
import urllib.request
import football_pages as pages
from identity_staging_provision import load_existing
from chronicles_api_provision import resolve_vault
from oci_control_plane import config_from_env, resolve_existing_host

KEY='SHADOWOPS_FOOTBALL_SERVICE_CREDENTIAL'
ISSUER='https://id-staging.shadowops.dpdns.org'

def activate(sdk,env,*,reader=load_existing):
 config=config_from_env(sdk,env)
 compartment,_=resolve_existing_host(sdk,config)
 vault,_,_=resolve_vault(sdk,config,compartment)
 bundle=reader(sdk,config,vault,compartment)
 if not bundle or 'football' not in bundle.get('consumers',{}):
  raise RuntimeError('Football Identity consumer has not been explicitly provisioned')
 # Prove that the deployed IdP has activated the pinned Football origin before
 # copying a service proof. Do not infer activation from Vault presence alone.
 request=urllib.request.Request(ISSUER+'/login?app=football',headers={'User-Agent':'ShadowOps-Football-Delivery/1.0'})
 with urllib.request.urlopen(request,timeout=15) as response:
  body=response.read(65537)
  if response.status!=200 or len(body)>65536 or b'https://staging.football.shadowops.dpdns.org/?shadowops=central' not in body:
   raise RuntimeError('Deployed Identity Football consumer is unavailable')
 if not pages.existing_project():raise RuntimeError('Dedicated Football Pages project is missing')
 _,project=pages.request('GET',pages.project_path())
 production=project.get('deployment_configs',{}).get('production',{})
 values=production.get('env_vars') or {}
 if not isinstance(values,dict) or set(values)-{KEY}:
  raise RuntimeError('Unknown Football Pages bindings require review')
 # The exact 48-character proof is the only operator value leaving this process.
 # Never send the full bundle, root/database/signing/backup keys or another app.
 pages.request('PATCH',pages.project_path(),{'deployment_configs':{'production':{'env_vars':{KEY:{'type':'secret_text','value':bundle['consumers']['football']}}}}})
 print('FOOTBALL_IDENTITY_EDGE_BINDING_CONFIGURED credential_logged=false')

if __name__=='__main__':
 try:
  import oci
  activate(oci,os.environ)
 except Exception as error:
  print('FOOTBALL_IDENTITY_BINDING_BLOCKED type='+type(error).__name__,file=sys.stderr)
  raise SystemExit(1)
