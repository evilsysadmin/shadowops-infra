#!/usr/bin/env python3
"""Independent Football admission and bounded static delivery; no OCI authority."""
from __future__ import annotations
import hashlib
import json
import mimetypes
import os
from pathlib import Path,PurePosixPath
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import football_pages as pages

REPO='evilsysadmin/football-of-matthias'
WORKFLOW='chess-football-godot-poc.yml'
HOST='staging.football.shadowops.dpdns.org'
BUCKET='chess-studio-assets'
PREFIX='football-of-matthias/staging'
CDN='https://assets.chess-studio.shadowops.dpdns.org'
HEX=re.compile(r'[a-f0-9]{40}')
AUTHENTICATION={'provider':'shadowops-id','audience':'football','required':True}
BUDGET=7_000_000_000
FOOTBALL_BUDGET=536_870_912
PUBLIC_HEADERS={'User-Agent':'ShadowOps-Football-Delivery/1.0 (+https://github.com/evilsysadmin/shadowops-infra)'}

class DeliveryError(ValueError):pass

def github(path):
 if not path.startswith('/repos/'+REPO+'/') or '..' in path:raise DeliveryError('Source path outside Football')
 request=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
 try:
  with urllib.request.urlopen(request,timeout=25) as response:return json.load(response)
 except Exception:raise DeliveryError('Football source evidence unavailable') from None

def public_release():
 request=urllib.request.Request('https://'+HOST+'/release.json',headers={**PUBLIC_HEADERS,'Cache-Control':'no-cache'})
 try:
  with urllib.request.urlopen(request,timeout=8) as response:return json.loads(response.read(65536))
 except (OSError,ValueError):return None

def admit(reader=github):
 current=reader(f'/repos/{REPO}/commits/main');sha=current.get('sha','')
 if not HEX.fullmatch(sha):raise DeliveryError('Full source SHA required')
 result=reader(f'/repos/{REPO}/actions/workflows/{WORKFLOW}/runs?'+urllib.parse.urlencode({'head_sha':sha,'branch':'main','event':'push','per_page':20}))
 for run in result.get('workflow_runs',[]):
  if (run.get('head_sha')!=sha or run.get('head_branch')!='main' or run.get('event')!='push'
      or run.get('status')!='completed' or run.get('conclusion')!='success'):continue
  rid=run.get('id')
  if type(rid) is not int:raise DeliveryError('Invalid source run')
  jobs=reader(f'/repos/{REPO}/actions/runs/{rid}/jobs?per_page=100').get('jobs',[])
  needed={'Football · required visual gate','Real Chromium · Godot Web boot','Manager · deterministic career and save isolation','validate'}
  passed={j.get('name') for j in jobs if j.get('conclusion')=='success' and j.get('completed_at')}
  if not needed<=passed:continue
  artifacts=reader(f'/repos/{REPO}/actions/runs/{rid}/artifacts?per_page=100').get('artifacts',[])
  matches=[a for a in artifacts if a.get('name')=='football-staging-'+sha and a.get('expired') is False]
  if len(matches)!=1:raise DeliveryError('Unique source artifact required')
  artifact=matches[0]
  if not re.fullmatch(r'sha256:[a-f0-9]{64}',artifact.get('digest','')):raise DeliveryError('Artifact digest required')
  return {'source_sha':sha,'run_id':rid,'artifact_id':artifact['id'],'artifact_digest':artifact['digest']}
 return None

def digest_file(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def validate(root,sha):
 if not HEX.fullmatch(sha):raise DeliveryError('Full source SHA required')
 root=root.resolve();manifest=json.loads((root/'delivery.json').read_text())
 if manifest.get('application')!='football-of-matthias' or manifest.get('environment')!='staging' or manifest.get('source_sha')!=sha:
  raise DeliveryError('Wrong source artifact identity')
 entries=manifest.get('files')
 if type(entries) is not dict or not 5<=len(entries)<=400:raise DeliveryError('Bounded artifact manifest required')
 actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.name!='delivery.json'}
 if actual!=set(entries) or any(p.is_symlink() for p in root.rglob('*')):raise DeliveryError('Extra, missing or symlink artifact file')
 total=0
 for name,item in entries.items():
  path=PurePosixPath(name)
  if path.is_absolute() or '..' in path.parts or path.parts[0] not in {'web','runtime'} or not re.fullmatch(r'[A-Za-z0-9_./-]+',name):raise DeliveryError('Unsafe artifact path')
  file=root/name
  if type(item) is not dict or type(item.get('bytes')) is not int or not 0<=item['bytes']<=100_000_000 or file.stat().st_size!=item['bytes'] or digest_file(file)!=item.get('sha256'):
   raise DeliveryError('Artifact bytes differ from source evidence')
  total+=item['bytes']
 if total>200_000_000:raise DeliveryError('Release exceeds bounded static budget')
 release=json.loads((root/'web/release.json').read_text());runtime=json.loads((root/'web/runtime.json').read_text())
 if release.get('authentication')!=AUTHENTICATION or not (root/'web/_worker.js').is_file():raise DeliveryError('ShadowOps ID edge gate required; anonymous release rejected')
 if release.get('source_sha')!=sha or release.get('application')!='football-of-matthias' or release.get('environment')!='staging' or release.get('runtime')!=runtime:raise DeliveryError('Frontend release differs from runtime')
 if runtime.get('version')!=1 or runtime.get('sourceSha')!=sha or not re.fullmatch(r'[a-f0-9]{16}',runtime.get('release','')):raise DeliveryError('Invalid runtime identity')
 expected=f'{CDN}/{PREFIX}/releases/{runtime["release"]}/index.html'
 if runtime.get('index')!=expected:raise DeliveryError('Runtime URL outside owned Football prefix')
 hashes=hashlib.sha256();runtime_entries={}
 for path in sorted((root/'runtime').rglob('*')):
  if not path.is_file():continue
  name=path.relative_to(root/'runtime').as_posix();raw=path.read_bytes()
  hashes.update(name.encode()+b'\0'+raw)
  runtime_entries[name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 if hashes.hexdigest()[:16]!=runtime['release'] or runtime_entries!=release.get('files'):
  raise DeliveryError('Runtime hash does not match immutable pointer')
 if not {'index.html','index.js','index.wasm','index.pck'}<=set(runtime_entries):raise DeliveryError('Incomplete Godot runtime')
 if any(p.stat().st_size>25*1024**2 for p in (root/'web').rglob('*') if p.is_file()):raise DeliveryError('Pages static-file budget exceeded')
 return release

def r2_request(method,path,*,data=None,content_type='application/json'):
 req=urllib.request.Request(pages.API+path,method=method,data=data,headers={'Authorization':'Bearer '+pages.required('FOOTBALL_R2_API_TOKEN'),'Content-Type':content_type,'Accept':'application/json','cf-r2-storage-class':'Standard'})
 try:
  with urllib.request.urlopen(req,timeout=60) as response:body=json.load(response)
 except urllib.error.HTTPError as error:raise DeliveryError('R2 operation rejected HTTP '+str(error.code)) from None
 except (OSError,ValueError):raise DeliveryError('R2 operation unavailable') from None
 if not isinstance(body,dict) or body.get('success') is False:raise DeliveryError('R2 operation failed')
 return body

def inventory(account):
 root=f'/accounts/{account}/r2/buckets/{BUCKET}/objects'
 values={};cursor=None;seen=set()
 for _ in range(100):
  query={'per_page':1000}
  if cursor:query['cursor']=cursor
  response=r2_request('GET',root+'?'+urllib.parse.urlencode(query))
  rows=response.get('result')
  if not isinstance(rows,list):raise DeliveryError('Complete R2 inventory required')
  for row in rows:
   key,size=row.get('key'),row.get('size')
   if type(key) is not str or not key or key in values or type(size) is not int or size<0:raise DeliveryError('Invalid R2 inventory')
   values[key]=size
  info=response.get('result_info',{})
  if info.get('is_truncated') is False or (not info.get('is_truncated') and len(rows)<1000):return values
  cursor=info.get('cursor')
  if not isinstance(cursor,str) or not cursor or cursor in seen:raise DeliveryError('Truncated R2 inventory')
  seen.add(cursor)
 raise DeliveryError('R2 inventory exceeds bounded scan')

def budget(current,additions):
 projected=sum(current.values())+sum(size-current.get(key,0) for key,size in additions.items())
 football=sum(size for key,size in current.items() if key.startswith(PREFIX+'/'))+sum(size-current.get(key,0) for key,size in additions.items())
 if projected>BUDGET or football>FOOTBALL_BUDGET:raise DeliveryError('Always Free headroom exhausted; no upload authorized')
 print(f'FOOTBALL_R2_FREE_CAPACITY projected_bytes={projected} football_bytes={football}')

def publish_runtime(root,sha):
 release=validate(root,sha);account=pages.required('CLOUDFLARE_ACCOUNT_ID')
 if not re.fullmatch('[a-f0-9]{32}',account):raise DeliveryError('Exact Cloudflare account required')
 prefix=PREFIX+'/releases/'+release['runtime']['release']+'/'
 additions={prefix+name:item['bytes'] for name,item in release['files'].items()}
 current=inventory(account);budget(current,additions) # before the first PUT
 for name,item in release['files'].items():
  path=root/'runtime'/name;key=prefix+name
  # Immutable payloads are never repointed to another game's path.
  content_type={'.wasm':'application/wasm','.pck':'application/octet-stream','.js':'text/javascript; charset=utf-8','.html':'text/html; charset=utf-8'}.get(path.suffix,mimetypes.guess_type(name)[0] or 'application/octet-stream')
  uri=f'/accounts/{account}/r2/buckets/{BUCKET}/objects/'+urllib.parse.quote(key,safe='/-._~')
  r2_request('PUT',uri,data=path.read_bytes(),content_type=content_type)
 print('FOOTBALL_R2_IMMUTABLE_RELEASE_UPLOADED source_sha='+sha)

def verify_public(sha):
 if not HEX.fullmatch(sha):raise DeliveryError('Exact source SHA required')
 deadline=time.monotonic()+420
 while time.monotonic()<deadline:
  current=public_release()
  if current and current.get('application')=='football-of-matthias' and current.get('environment')=='staging' and current.get('source_sha')==sha and current.get('authentication')==AUTHENTICATION:
   runtime=current.get('runtime',{});uri=runtime.get('index','')
   if uri!=f'{CDN}/{PREFIX}/releases/{runtime.get("release")}/index.html' or runtime.get('sourceSha')!=sha:raise DeliveryError('Public runtime identity mismatch')
   with urllib.request.urlopen(urllib.request.Request(uri,headers=PUBLIC_HEADERS),timeout=20) as response:
    if response.status==200 and b'Engine' in response.read(100000):
     print('FOOTBALL_STAGING_PUBLIC_VERIFIED source_sha='+sha+' host='+HOST);return
  time.sleep(8)
 raise DeliveryError('Public Football staging did not converge')

def main():
 action=sys.argv[1]
 if action=='candidate':
  candidate=admit()
  output=Path(os.environ['GITHUB_OUTPUT'])
  if candidate is None:
   with output.open('a') as f:f.write('publish=false\n')
   print('FOOTBALL_WAITING_FOR_SOURCE_CI');return
  current=public_release();publish=os.environ.get('FOOTBALL_FORCE_REDEPLOY')=='true' or not(current and current.get('source_sha')==candidate['source_sha'] and current.get('application')=='football-of-matthias' and current.get('authentication')==AUTHENTICATION)
  with output.open('a') as f:
   for key,value in candidate.items():f.write(f'{key}={value}\n')
   f.write('publish='+str(publish).lower()+'\n')
  print('FOOTBALL_SOURCE_ADMITTED source_sha='+candidate['source_sha']+' publish='+str(publish).lower())
 elif action=='validate':validate(Path(sys.argv[2]),sys.argv[3]);print('FOOTBALL_ARTIFACT_BYTES_VERIFIED')
 elif action=='runtime':publish_runtime(Path(sys.argv[2]),sys.argv[3])
 elif action=='verify':verify_public(sys.argv[2])
 else:raise DeliveryError('Unknown Football delivery operation')

if __name__=='__main__':
 try:main()
 except Exception as error:
  print('FOOTBALL_DELIVERY_BLOCKED '+(str(error) if isinstance(error,DeliveryError) else 'type='+type(error).__name__),file=sys.stderr);raise SystemExit(1)
