import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import football_delivery as delivery
import football_pages as pages
SHA='a'*40

def fixture(root):
 for folder in ['web','runtime']:(root/folder).mkdir()
 for name,raw in [('index.html',b'<html>Engine</html>'),('index.js',b'engine'),('index.wasm',b'wasm'),('index.pck',b'pck')]:
  (root/'runtime'/name).write_bytes(raw)
 hashes=hashlib.sha256();entries={}
 for p in sorted((root/'runtime').iterdir()):
  raw=p.read_bytes();hashes.update(p.name.encode()+b'\0'+raw)
  entries[p.name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 release_id=hashes.hexdigest()[:16]
 pointer={'version':1,'release':release_id,'sourceSha':SHA,'index':f'{delivery.CDN}/{delivery.PREFIX}/releases/{release_id}/index.html'}
 release={'application':'football-of-matthias','environment':'staging','source_sha':SHA,'authentication':delivery.AUTHENTICATION,'runtime':pointer,'files':entries}
 (root/'web/_worker.js').write_text('export default {fetch(){return new Response("authentication required",{status:401})}}')
 (root/'web/release.json').write_text(json.dumps(release));(root/'web/runtime.json').write_text(json.dumps(pointer));(root/'web/index.html').write_text('Football')
 files={p.relative_to(root).as_posix():{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in root.rglob('*') if p.is_file()}
 (root/'delivery.json').write_text(json.dumps({'application':'football-of-matthias','environment':'staging','source_sha':SHA,'files':files}))
 return release

class FootballDelivery(unittest.TestCase):
 def test_public_runtime_exact_bytes_and_manifest(self):
  import io
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);release=fixture(root)
   seen=[]
   def response(request,**kwargs):
    name=request.full_url.rsplit('/',1)[-1];seen.append(name)
    result=io.BytesIO((root/'runtime'/name).read_bytes())
    result.status=200;result.geturl=lambda:request.full_url
    return result
   with patch.object(delivery,'public_release',return_value=release),patch.object(delivery.urllib.request,'urlopen',side_effect=response):
    delivery.verify_public(SHA,root)
   self.assertEqual(seen,['index.html','index.js','index.wasm','index.pck'])
   stale=copy.deepcopy(release);stale['files']['index.pck']['sha256']='b'*64
   with patch.object(delivery,'public_release',return_value=stale),patch.object(delivery.urllib.request,'urlopen') as request:
    with self.assertRaisesRegex(delivery.DeliveryError,'manifest differs'):delivery.verify_public(SHA,root)
    request.assert_not_called()
   for fault in ['same_size','oversize','truncated','redirect','status']:
    with self.subTest(fault=fault):
     def corrupt(request,**kwargs):
      result=response(request,**kwargs)
      if request.full_url.endswith('/index.pck'):
       if fault in ['same_size','oversize','truncated']:
        result=io.BytesIO({'same_size':b'old','oversize':b'oldpack','truncated':b'p'}[fault])
        result.status=200;result.geturl=lambda:request.full_url
       elif fault=='redirect':result.geturl=lambda:'https://example.invalid/index.pck'
       else:result.status=206
      return result
     with patch.object(delivery,'public_release',return_value=release),patch.object(delivery.urllib.request,'urlopen',side_effect=corrupt):
      with self.assertRaisesRegex(delivery.DeliveryError,'index.pck'):delivery.verify_public(SHA,root)
 def test_prepublish_runtime_is_bounded_and_fail_closed(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);release=fixture(root)
   failure=delivery.DeliveryError('Public runtime size mismatch: index.html')
   with patch.object(delivery,'verify_runtime_bytes',side_effect=[failure,None]) as verify,patch.object(delivery.time,'sleep') as sleep:
    delivery.verify_before_publish(root,SHA)
    self.assertEqual(verify.call_count,2)
    self.assertEqual(verify.call_args.args,(release,))
    sleep.assert_called_once_with(5)
   with patch.object(delivery,'verify_runtime_bytes',side_effect=failure) as verify,patch.object(delivery.time,'sleep') as sleep:
    with self.assertRaisesRegex(delivery.DeliveryError,'index.html'):delivery.verify_before_publish(root,SHA)
    self.assertEqual(verify.call_count,3)
    self.assertEqual([x.args[0] for x in sleep.call_args_list],[5,15])
 def test_runtime_upload_preserves_origin_no_transform_metadata(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);release=fixture(root)
   with patch.dict(os.environ,{'CLOUDFLARE_ACCOUNT_ID':'a'*32}),patch.object(delivery,'inventory',return_value={}),patch.object(delivery,'r2_request') as request:
    delivery.publish_runtime(root,SHA)
   self.assertEqual(request.call_count,len(release['files']))
   for call in request.call_args_list:
    self.assertEqual(call.args[0],'PUT')
    self.assertIn('/objects/'+delivery.PREFIX+'/releases/'+release['runtime']['release']+'/',call.args[1])
    self.assertIn('no-transform',call.kwargs['cache_control'])
    self.assertIn('immutable',call.kwargs['cache_control'])
    name=call.args[1].rsplit('/',1)[-1]
    self.assertEqual(call.kwargs['data'],(root/'runtime'/name).read_bytes())
 def test_cache_metadata_is_sent_only_for_owned_runtime_put(self):
  import io
  seen=[]
  def response(request,**kwargs):
   seen.append(request)
   return io.BytesIO(b'{"success":true}')
  uri='/accounts/'+'a'*32+'/r2/buckets/'+delivery.BUCKET+'/objects/'+delivery.PREFIX+'/releases/1234567890abcdef/index.html'
  with patch.object(pages,'required',return_value='test-token'),patch.object(delivery.urllib.request,'urlopen',side_effect=response):
   delivery.r2_request('PUT',uri,data=b'html',content_type='text/html',cache_control=delivery.RUNTIME_CACHE_CONTROL)
   self.assertEqual(seen[0].get_header('Cache-control'),delivery.RUNTIME_CACHE_CONTROL)
   with self.assertRaises(delivery.DeliveryError):
    delivery.r2_request('PUT','/objects/other-game/index.html',data=b'html',cache_control=delivery.RUNTIME_CACHE_CONTROL)
   with self.assertRaises(delivery.DeliveryError):
    delivery.r2_request('GET',uri,cache_control=delivery.RUNTIME_CACHE_CONTROL)
   self.assertEqual(len(seen),1)
 def test_exact_artifact_and_immutable_runtime_hash(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);release=fixture(root)
   self.assertEqual(delivery.validate(root,SHA),release)
   (root/'runtime/index.wasm').write_bytes(b'foreign')
   with self.assertRaises(delivery.DeliveryError):delivery.validate(root,SHA)
 def test_wrong_source_extra_file_and_symlink_rejected(self):
  for fault in ['source','extra','symlink']:
   with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);fixture(root)
    if fault=='extra':(root/'web/unreviewed.js').write_text('injected')
    if fault=='symlink':(root/'runtime/leak').symlink_to('/etc/passwd')
    with self.assertRaises(delivery.DeliveryError):delivery.validate(root,'b'*40 if fault=='source' else SHA)
 def test_anonymous_source_is_rejected_even_when_artifact_hashes_match(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);fixture(root)
   release=json.loads((root/'web/release.json').read_text());release.pop('authentication')
   (root/'web/release.json').write_text(json.dumps(release))
   manifest=json.loads((root/'delivery.json').read_text());file=root/'web/release.json'
   manifest['files']['web/release.json']={'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'bytes':file.stat().st_size}
   (root/'delivery.json').write_text(json.dumps(manifest))
   with self.assertRaises(delivery.DeliveryError):delivery.validate(root,SHA)
 def test_edge_quota_exhaustion_cannot_expose_unprotected_assets(self):
  project={'deployment_configs':{mode:{'fail_open':False,'compatibility_flags':['global_fetch_strictly_public']} for mode in ('production','preview')}}
  with patch.object(pages,'existing_project',return_value=True),patch.object(pages,'project_path',return_value='/owned'),patch.object(pages,'request',return_value=(200,project)) as request:
   pages.ensure_identity_policy()
   self.assertEqual(request.call_args_list[1].args,('PATCH','/owned',project))
   project['deployment_configs']['production']['fail_open']=True
   with self.assertRaises(RuntimeError):pages.ensure_identity_policy()
 def test_public_identity_routing_preserves_other_flags_and_rejects_private_override(self):
  project={'deployment_configs':{mode:{'fail_open':False,'compatibility_flags':['global_fetch_strictly_public','nodejs_compat']} for mode in ('production','preview')}}
  with patch.object(pages,'existing_project',return_value=True),patch.object(pages,'project_path',return_value='/owned'),patch.object(pages,'request',return_value=(200,project)) as request:
   pages.ensure_identity_policy()
   self.assertEqual(request.call_args_list[1].args[2],project)
   project['deployment_configs']['preview']['compatibility_flags'].append('global_fetch_private_origin')
   request.reset_mock()
   with self.assertRaises(RuntimeError):pages.ensure_identity_policy()
   self.assertFalse(any(call.args[0]=='PATCH' for call in request.call_args_list))
 def test_budget_counts_shared_bucket_and_own_prefix_with_no_bypass(self):
  delivery.budget({'other/keep':1},{delivery.PREFIX+'/new':1})
  with self.assertRaises(delivery.DeliveryError):delivery.budget({'other/keep':delivery.BUDGET},{delivery.PREFIX+'/new':1})
  with self.assertRaises(delivery.DeliveryError):delivery.budget({},{delivery.PREFIX+'/new':delivery.FOOTBALL_BUDGET+1})
 def test_foreign_dns_or_project_cannot_be_adopted(self):
  with patch.object(pages,'dns_path',return_value='/dns'),patch.object(pages,'request',return_value=(200,[{'name':pages.HOST,'type':'CNAME','proxied':True,'content':'another.pages.dev'}])):
   with self.assertRaises(RuntimeError):pages.dns_record()
  with patch.dict(os.environ,{'CLOUDFLARE_ACCOUNT_ID':'a'*32}),patch.object(pages,'request',return_value=(200,{'name':pages.PROJECT,'production_branch':'main','domains':['another.shadowops.dpdns.org']})):
   with self.assertRaises(RuntimeError):pages.existing_project()
 def test_source_admission_requires_exact_main_successful_push_and_all_gates(self):
  def reader(path):
   if path.endswith('/commits/main'):return {'sha':SHA}
   if '/workflows/' in path:return {'workflow_runs':[{'id':5 if delivery.XI_WORKFLOW in path else 4,'head_sha':SHA,'head_branch':'main','event':'push','status':'completed','conclusion':'success'}]}
   if '/jobs?' in path:
    names=[delivery.XI_CHECK] if '/runs/5/' in path else ['Football · required visual gate','Real Chromium · Godot Web boot','Manager · deterministic career and save isolation','validate']
    return {'jobs':[{'name':n,'status':'completed','conclusion':'success','completed_at':'today'} for n in names]}
   if '/artifacts?' in path:return {'artifacts':[{'id':7,'name':'football-staging-'+SHA,'expired':False,'digest':'sha256:'+'b'*64}]}
   raise AssertionError(path)
  self.assertEqual(delivery.admit(reader)['source_sha'],SHA)
  for fault in ['pr','sha','gate','artifact']:
   def changed(path):
    value=reader(path)
    if fault=='pr' and '/workflows/' in path:value['workflow_runs'][0]['event']='pull_request'
    if fault=='sha' and '/workflows/' in path:value['workflow_runs'][0]['head_sha']='b'*40
    if fault=='gate' and '/runs/4/jobs?' in path:value['jobs']=[]
    if fault=='artifact' and '/artifacts?' in path:value['artifacts']=[]
    return value
   if fault=='artifact':
    with self.assertRaises(delivery.DeliveryError):delivery.admit(changed)
   else:self.assertIsNone(delivery.admit(changed))
 def test_xi_separate_workflow_must_be_green_on_exact_main_push(self):
  def clean(path):
   if path.endswith('/commits/main'):return {'sha':SHA}
   if '/workflows/' in path:return {'workflow_runs':[{'id':5 if delivery.XI_WORKFLOW in path else 4,'head_sha':SHA,'head_branch':'main','event':'push','status':'completed','conclusion':'success'}]}
   if '/jobs?' in path:
    names=[delivery.XI_CHECK] if '/runs/5/' in path else ['Football · required visual gate','Real Chromium · Godot Web boot','Manager · deterministic career and save isolation','validate']
    return {'jobs':[{'name':n,'status':'completed','conclusion':'success','completed_at':'today'} for n in names]}
   if '/artifacts?' in path:return {'artifacts':[{'id':7,'name':'football-staging-'+SHA,'expired':False,'digest':'sha256:'+'b'*64}]}
   raise AssertionError(path)
  self.assertEqual(delivery.admit(clean)['source_sha'],SHA)
  for fault in ['missing_run','pending','failed','skipped','wrong_sha','wrong_branch','pr','missing_job','job_failed','job_pending','job_incomplete']:
   with self.subTest(fault=fault):
    def reader(path):
     value=clean(path)
     if delivery.XI_WORKFLOW in path and '/workflows/' in path:
      run=value['workflow_runs'][0]
      if fault=='missing_run':value['workflow_runs']=[]
      if fault=='pending':run.update(status='in_progress',conclusion=None)
      if fault=='failed':run.update(status='completed',conclusion='failure')
      if fault=='skipped':run.update(status='completed',conclusion='skipped')
      if fault=='wrong_sha':run['head_sha']='b'*40
      if fault=='wrong_branch':run['head_branch']='other'
      if fault=='pr':run['event']='pull_request'
     if '/runs/5/jobs?' in path:
      if fault=='missing_job':value['jobs']=[]
      if fault=='job_failed':value['jobs'][0]['conclusion']='failure'
      if fault=='job_pending':value['jobs'][0]['status']='in_progress'
      if fault=='job_incomplete':value['jobs'][0]['completed_at']=None
     return value
    self.assertIsNone(delivery.admit(reader),'Must fail closed before staging publication')
 def test_pages_generated_subdomain_is_used_without_adopting_foreign_domains(self):
  project={'name':pages.PROJECT,'production_branch':'main','subdomain':'football-staging-aha.pages.dev','domains':['football-staging-aha.pages.dev']}
  with patch.dict(os.environ,{'CLOUDFLARE_ACCOUNT_ID':'a'*32}),patch.object(pages,'request',return_value=(200,project)):
   self.assertTrue(pages.existing_project())
   self.assertEqual(pages.dns_target(),'football-staging-aha.pages.dev')
   project['domains'].append('someone-else.pages.dev')
   with self.assertRaises(RuntimeError):pages.existing_project()
  with self.assertRaises(RuntimeError):pages.project_target({'subdomain':'another.pages.dev'})
 def test_public_probe_identifies_itself_without_default_python_bot_signature(self):
  import io
  from contextlib import contextmanager
  seen=[]
  @contextmanager
  def response(request,**kwargs):
   seen.append(request)
   yield io.BytesIO(b'{"application":"football-of-matthias"}')
  with patch.object(delivery.urllib.request,'urlopen',side_effect=response):
   self.assertEqual(delivery.public_release()['application'],'football-of-matthias')
  self.assertEqual(seen[0].get_header('User-agent'),delivery.PUBLIC_HEADERS['User-Agent'])
 def test_upload_never_creates_compute_bucket_tunnel_or_deletes_others(self):
  source=(ROOT/'scripts/football_delivery.py').read_text()
  self.assertNotIn("r2_request('DELETE'",source)
  self.assertIn('before the first PUT',source)
  self.assertNotIn('import oci',source)

if __name__=='__main__':unittest.main()
