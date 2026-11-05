"""Real disposable Docker service/Mongo stack, zero public ports and no real secrets."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from identity_staging_bundle import generate,service_config,enable_admin_inventory
import identity_staging_backup as backup
import identity_staging_atlas_journey as journey
from unittest.mock import patch
from identity_staging_atlas_policy import validate_atlas_compose, AtlasPolicyError
spec=importlib.util.spec_from_file_location('identity_host_stack',ROOT/'host/identity-staging-deploy.py')
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


@unittest.skipUnless(os.environ.get('IDENTITY_STACK_TEST')=='1','explicit disposable Docker stack not requested')
class StackTests(unittest.TestCase):
 def test_normalized_compose_rejects_host_authority_and_foreign_images(self):
  import yaml
  with tempfile.TemporaryDirectory(prefix='identity-compose-test-') as temp:
   path=Path(temp)
   policy=yaml.safe_load((ROOT/'compose.identity.staging.yaml').read_text())
   (path/'synthetic.env').write_text('TUNNEL_TOKEN=synthetic-compose-token\n')
   policy['services']['identity-tunnel']['env_file']=[str(path/'synthetic.env')]
   (path/'compose.yaml').write_text(yaml.safe_dump(policy))
   result=subprocess.run(['docker','compose','-f',str(path/'compose.yaml'),'config','--format','json'],env={**os.environ,'IDENTITY_IMAGE_DIGEST':'sha256:'+'a'*64},capture_output=True,text=True,timeout=30)
   self.assertEqual(result.returncode,0,result.stderr)
   config=json.loads(result.stdout)
   host.assert_compose(config,'sha256:'+'a'*64)
   for scenario in ['host-port','socket','image','root','public-db']:
    changed=copy.deepcopy(config)
    if scenario=='host-port':changed['services']['identity']['ports']=[{'published':'9443','target':9443}]
    if scenario=='socket':changed['services']['identity']['volumes'].append({'source':'/var/run/docker.sock','target':'/var/run/docker.sock','type':'bind'})
    if scenario=='image':changed['services']['identity']['image']='foreign:latest'
    if scenario=='root':changed['services']['identity']['user']='0:0'
    if scenario=='public-db':changed['networks']['database']['internal']=False
    with self.subTest(scenario=scenario),self.assertRaises(host.DeployError):host.assert_compose(changed,'sha256:'+'a'*64)

 def test_atlas_evaluation_egress_never_admitted_by_current_staging_wrapper(self):
  import yaml
  with tempfile.TemporaryDirectory(prefix='identity-atlas-compose-') as temp:
   path=Path(temp)
   base=yaml.safe_load((ROOT/'compose.identity.staging.yaml').read_text())
   (path/'synthetic.env').write_text('TUNNEL_TOKEN=synthetic-compose-token\n')
   base['services']['identity-tunnel']['env_file']=[str(path/'synthetic.env')]
   (path/'compose.yaml').write_text(yaml.safe_dump(base))
   result=subprocess.run(['docker','compose','-f',str(path/'compose.yaml'),'-f',str(ROOT/'compose.identity.staging.atlas-evaluation.yaml'),'config','--format','json'],env={**os.environ,'IDENTITY_IMAGE_DIGEST':'sha256:'+'a'*64},capture_output=True,text=True,timeout=30)
   self.assertEqual(result.returncode,0,result.stderr)
   config=json.loads(result.stdout)
   self.assertIn('atlas-egress',config['services']['identity']['networks'])
   self.assertNotIn('atlas-egress',config['services']['identity-mongo']['networks'])
   self.assertNotIn('atlas-egress',config['services']['identity-tunnel']['networks'])
   self.assertFalse(config['networks']['atlas-egress'].get('internal',False))
   with self.assertRaises(host.DeployError):host.assert_compose(config,'sha256:'+'a'*64)

 def test_atlas_candidate_has_only_service_and_tunnel_and_is_not_admitted_by_local_guard(self):
  import yaml
  with tempfile.TemporaryDirectory(prefix='identity-atlas-candidate-') as temp:
   path=Path(temp)
   policy=yaml.safe_load((ROOT/'compose.identity.atlas.staging.yaml').read_text())
   (path/'synthetic.env').write_text('TUNNEL_TOKEN=synthetic-compose-token\n')
   policy['services']['identity-tunnel']['env_file']=[str(path/'synthetic.env')]
   (path/'compose.yaml').write_text(yaml.safe_dump(policy))
   result=subprocess.run(['docker','compose','-f',str(path/'compose.yaml'),'config','--format','json'],env={**os.environ,'IDENTITY_IMAGE_DIGEST':'sha256:'+'a'*64},capture_output=True,text=True,timeout=30)
   self.assertEqual(result.returncode,0,result.stderr)
   config=json.loads(result.stdout)
   self.assertEqual(set(config['services']),{'identity','identity-tunnel'})
   self.assertEqual(set(config['services']['identity']['networks']),{'origin','atlas-egress'})
   self.assertEqual(set(config['services']['identity-tunnel']['networks']),{'origin','tunnel-egress'})
   self.assertTrue(config['networks']['origin']['internal'])
   self.assertFalse(config['networks']['atlas-egress'].get('internal',False))
   for service in config['services'].values():
    self.assertFalse(service.get('ports'))
    self.assertTrue(service['read_only'])
    self.assertEqual(service['cap_drop'],['ALL'])
    self.assertIn('no-new-privileges:true',service['security_opt'])
   self.assertNotIn('volumes',config)
   with self.assertRaises(host.DeployError):host.assert_compose(config,'sha256:'+'a'*64)
   digest='sha256:'+'a'*64
   validate_atlas_compose(config,digest)
   for scenario in ('port','socket','wrong-network','wrong-image','privileged','writable-root','extra-env','extra-service','unprotected-origin','wrong-alias','network-driver','excess-memory'):
    changed=copy.deepcopy(config)
    if scenario=='port':changed['services']['identity']['ports']=[{'published':'27017','target':27017}]
    if scenario=='socket':changed['services']['identity']['volumes'].append({'type':'bind','source':'/var/run/docker.sock','target':'/socket','read_only':False})
    if scenario=='wrong-network':changed['services']['identity']['networks']['tunnel-egress']={}
    if scenario=='wrong-image':changed['services']['identity']['image']='foreign:latest'
    if scenario=='privileged':changed['services']['identity']['privileged']=True
    if scenario=='writable-root':changed['services']['identity']['read_only']=False
    if scenario=='extra-env':changed['services']['identity']['environment']={'EXTRA':'bad'}
    if scenario=='extra-service':changed['services']['extra']={}
    if scenario=='unprotected-origin':changed['networks']['origin']['internal']=False
    if scenario=='wrong-alias':changed['services']['identity']['networks']['origin']['aliases']=['foreign.example']
    if scenario=='network-driver':changed['networks']['atlas-egress']['driver_opts']={'unsafe':'true'}
    if scenario=='excess-memory':changed['services']['identity']['mem_limit']='99999999999'
    with self.subTest(scenario=scenario),self.assertRaises(AtlasPolicyError):validate_atlas_compose(changed,digest)

 def test_private_tls_image_account_revocation_and_database_persistence(self):
  prefix='identity-stack-test-'+secrets.token_hex(5)
  network='shadowops-identity-atlas-canary-net-'+secrets.token_hex(12); mongo=prefix+'-mongo'; identity=prefix+'-service'
  database=prefix+'-data'; config_volume=prefix+'-config'; image=prefix+':fixture'
  bundle=generate('disposable-token-'+'a'*64)
  containers=[];volumes=[];network_created=False;image_created=False
  def docker(*args,data=None,timeout=180):
   result=subprocess.run(['docker',*args],input=data,capture_output=True,text=True,timeout=timeout)
   if result.returncode:
    raise AssertionError('Disposable Docker operation failed: '+args[0]+'\n'+result.stderr[-1500:])
   return result.stdout.strip()
  def quiet(*args):subprocess.run(['docker',*args],capture_output=True,timeout=60)
  def shell(script):return docker('exec','-i',mongo,'mongosh','--quiet','--norc','--tls','--tlsCAFile','/tmp/ca.pem','mongodb://127.0.0.1:27017/?directConnection=true','--file','/dev/stdin',data=script,timeout=100)
  def healthy():
   for _ in range(45):
    state=subprocess.run(['docker','exec',identity,'/app/identity','healthcheck'],capture_output=True,timeout=5)
    if state.returncode==0:return
    time.sleep(1)
   raise AssertionError('Disposable real Identity did not become ready')
  try:
   docker('build','--build-arg','IDENTITY_SOURCE_SHA='+'a'*40,'--tag',image,str(ROOT/'services/identity'),timeout=480);image_created=True
   docker('network','create','--internal',network);network_created=True
   for volume in (database,config_volume):docker('volume','create',volume);volumes.append(volume)
   with tempfile.TemporaryDirectory(prefix='identity-stack-material-') as temp:
    path=Path(temp)
    material={'ca.pem':bundle['ca_certificate_pem'],'mongo.pem':bundle['mongo_certificate_key_pem'],'replica.key':bundle['mongo_replica_key'],'service.json':json.dumps(service_config(bundle))}
    for name,value in material.items():(path/name).write_text(value)
    docker('run','--rm','--network','none','--mount','type=volume,src='+config_volume+',dst=/out','--mount','type=bind,src='+temp+',dst=/fixture,readonly','--entrypoint','bash',host.MONGO_IMAGE,'-c','cp /fixture/service.json /out/service.json && chown 65532:65532 /out/service.json && chmod 400 /out/service.json')
    docker('run','-d','--name',mongo,'--network',network,'--network-alias','identity-mongo','--mount','type=volume,src='+database+',dst=/data/db','--mount','type=bind,src='+temp+',dst=/fixture,readonly','--entrypoint','bash',host.MONGO_IMAGE,'-c','cp /fixture/ca.pem /tmp/ca.pem && cp /fixture/mongo.pem /tmp/mongo.pem && cp /fixture/replica.key /tmp/replica.key && chown mongodb:mongodb /tmp/mongo.pem /tmp/replica.key /data/db && chmod 400 /tmp/mongo.pem /tmp/replica.key && exec gosu mongodb mongod --replSet identity-staging-rs --bind_ip_all --wiredTigerCacheSizeGB 0.25 --keyFile /tmp/replica.key --tlsMode requireTLS --tlsCertificateKeyFile /tmp/mongo.pem --tlsCAFile /tmp/ca.pem --tlsAllowConnectionsWithoutCertificates');containers.append(mongo)
    for attempt in range(45):
     try:
      shell('if (db.adminCommand({ping:1}).ok !== 1) quit(1);');break
     except AssertionError:
      if attempt==44:raise
      time.sleep(1)
    self.assertIn('IDENTITY_STAGING_DATABASE_READY',shell(host.bootstrap_script(bundle)))
    self.assertIn('IDENTITY_STAGING_DATABASE_READY',shell(host.bootstrap_script(bundle)))
    wrong=copy.deepcopy(bundle);wrong['mongo_root_password']='b'*64
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(wrong))
    wrong=copy.deepcopy(bundle);wrong['mongo_application_password']='c'*64
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(wrong))
    # Exercise the exact synthetic role grant and scoped cleanup through a
    # disposable authenticated TLS replica. The network is internal only.
    canary_name='identitycanary_'+secrets.token_hex(8)
    canary_subject='11111111-1111-4111-8111-111111111111'
    decoy_subject='22222222-2222-4222-8222-222222222222'
    setup='const a=db.getSiblingDB("admin"); a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); const d=db.getSiblingDB("shadowops_identity_staging"); '
    setup+='d.pending_accounts.insertMany('+json.dumps([
      {'_id':canary_subject,'environment':'staging','source':'shadowops-identity','alias_key':canary_name,'state':'active','credentials_disabled':False,'role':'user'},
      {'_id':decoy_subject,'environment':'staging','source':'shadowops-identity','alias_key':'decoy_user','state':'active','credentials_disabled':False,'role':'user'}])+'); '
    setup+='d.sessions.insertOne({environment:"staging",subject:'+json.dumps(canary_subject)+',digest:"synthetic-session"}); '
    setup+='d.admin_inventory_audit.insertOne({_id:"synthetic-audit",actor:'+json.dumps(canary_subject)+'});'
    shell(setup)
    local_uri='mongodb://identity_root:'+bundle['mongo_root_password']+'@identity-mongo:27017/shadowops_identity_staging?tls=true&tlsCAFile=/tmp/rehearsal-ca.pem&authSource=admin&replicaSet=identity-staging-rs'
    def tls_runner(args,**kwargs):
     args=list(args);i=args.index(journey.IMAGE)
     args[i:i]=['--mount','type=bind,src='+str(path/'ca.pem')+',dst=/tmp/rehearsal-ca.pem,readonly']
     return subprocess.run(args,**kwargs)
    with patch.object(journey,'_connection',return_value=('fixture','fixture')):
     subject=journey.mongo_action(local_uri,network,canary_name,'lookup',runner=tls_runner)
     self.assertEqual(subject,canary_subject)
     journey.mongo_action(local_uri,network,canary_name,'promote',subject,runner=tls_runner)
     self.assertIn('CANARY_ROLE_VERIFIED',shell('const a=db.getSiblingDB("admin");a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); if(db.getSiblingDB("shadowops_identity_staging").pending_accounts.findOne({_id:'+json.dumps(canary_subject)+'}).role!=="admin") throw Error("role"); print("CANARY_ROLE_VERIFIED");'))
     journey.mongo_action(local_uri,network,canary_name,'cleanup',subject,runner=tls_runner)
    verify='const a=db.getSiblingDB("admin");a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+');const d=db.getSiblingDB("shadowops_identity_staging"); '
    verify+='if(d.pending_accounts.findOne({_id:'+json.dumps(canary_subject)+'}) || d.sessions.findOne({subject:'+json.dumps(canary_subject)+'}) || !d.pending_accounts.findOne({_id:'+json.dumps(decoy_subject)+'}) || !d.admin_inventory_audit.findOne({_id:"synthetic-audit"})) throw Error("cleanup"); '
    verify+='d.pending_accounts.deleteOne({_id:'+json.dumps(decoy_subject)+'});d.admin_inventory_audit.deleteOne({_id:"synthetic-audit"}); print("CANARY_CLEANUP_VERIFIED");'
    self.assertIn('CANARY_CLEANUP_VERIFIED',shell(verify))
    docker('run','-d','--name',identity,'--network',network,'--network-alias','identity','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--mount','type=volume,src='+config_volume+',dst=/run/secrets,readonly','-e','IDENTITY_STAGING_CONFIG_FILE=/run/secrets/service.json',image);containers.append(identity)
    healthy()
    # Node's real TLS client in mongosh authenticates the actual IdP certificate.
    # No route interception, fake authority or forwarded-TLS shortcut.
    node='''
(async function () {
const https=require('https');
const assert=require('assert');
const fs=require('fs');
const credential=CONSUMER;
const origin='https://staging.chronicles.shadowops.dpdns.org';
const central='https://id-staging.shadowops.dpdns.org';
const credentials={username:'stack_player',password:'synthetic-staging-stack-password-2026'};
async function call(path,body,requestOrigin,cookie,serverCredential,expected) {
 const headers={'Host':'id-staging.shadowops.dpdns.org','Content-Type':'application/json'};
 if (requestOrigin) headers.Origin=requestOrigin;
 if (cookie) headers.Cookie=cookie;
 if (serverCredential) headers.Authorization='Bearer '+serverCredential;
 const result=await new Promise((resolve,reject)=>{
  const r=https.request({host:'identity',port:9443,servername:'id-staging.shadowops.dpdns.org',ca:fs.readFileSync('/tmp/ca.pem'),path,method:'POST',headers},res=>{
   let text='';res.on('data',chunk=>text+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:text}));
  });r.on('error',reject);r.end(JSON.stringify(body));
 });
 assert.equal(result.status,expected,'real Identity status for '+path);
 return result;
}
if (REGISTER) await call('/api/identity/register',credentials,central,null,null,201);
const login=await call('/api/identity/login',credentials,central,null,null,204);
assert(login.headers['set-cookie'][0].includes('HttpOnly'));
const cookie=login.headers['set-cookie'][0].split(';')[0];
const token=JSON.parse((await call('/api/identity/token',{},origin,cookie,null,200)).body).token;
const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
const proof={subject:claims.sub,session_version:claims.sv,token_jti:claims.jti};
await call('/api/identity/freshness',proof,null,null,credential,200);
await call('/api/identity/logout',{},origin,cookie,null,204);
await call('/api/identity/freshness',proof,null,null,credential,401);
print('REAL_IMAGE_ACCOUNT_SESSION_AND_REVOCATION_OK');
})().catch(error => { print('REAL_IMAGE_REQUEST_FAILED ' + error.message); quit(1); });
'''.replace('CONSUMER',json.dumps(bundle['consumers']['chronicles']))
    self.assertIn('REAL_IMAGE_ACCOUNT_SESSION_AND_REVOCATION_OK',shell(node.replace('REGISTER','true')))
    docker('stop',identity)
    docker('restart',mongo)
    # Reusing the same durable volume must preserve the account and exact role.
    for attempt in range(45):
     try:
      shell('if (!db.hello().isWritablePrimary) quit(1);');break
     except AssertionError:
      if attempt==44:raise
      time.sleep(1)
    docker('start',identity);healthy()
    self.assertIn('REAL_IMAGE_ACCOUNT_SESSION_AND_REVOCATION_OK',shell(node.replace('REGISTER','false')))
    # Enable only the synthetic admin service after an existing account exists.
    # Repeated bootstrap preserves credentials and never grants an admin role.
    docker('stop',identity)
    base_bundle=copy.deepcopy(bundle)
    bundle=enable_admin_inventory(bundle)
    self.assertIn('IDENTITY_STAGING_DATABASE_READY',shell(host.bootstrap_script(bundle)))
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(base_bundle))
    self.assertIn('IDENTITY_STAGING_DATABASE_READY',shell(host.bootstrap_script(bundle)))
    root_prefix='const a=db.getSiblingDB("admin"); a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); const d=db.getSiblingDB("shadowops_identity_staging"); '
    shell(root_prefix+'d.admin_inventory_audit.createIndex({at:1},{expireAfterSeconds:60,name:"unsafe_ttl"});')
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(bundle))
    shell(root_prefix+'d.admin_inventory_audit.dropIndex("unsafe_ttl"); d.grantRolesToUser("identity_inventory",[{role:"read",db:d.getName()}]);')
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(bundle))
    shell(root_prefix+'d.revokeRolesFromUser("identity_inventory",[{role:"read",db:d.getName()}]);')
    wrong=copy.deepcopy(bundle);wrong['admin_inventory']['mongo_password']='d'*64
    with self.assertRaises(AssertionError):shell(host.bootstrap_script(wrong))
    shell('const a=db.getSiblingDB("admin"); a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); const d=db.getSiblingDB("shadowops_identity_staging"); if (d.pending_accounts.findOne({alias_key:"stack_player"}).role!=="user") quit(1); d.pending_accounts.updateOne({alias_key:"stack_player"},{$set:{role:"admin"}});')
    (path/'service.json').write_text(json.dumps(service_config(bundle)))
    docker('run','--rm','--network','none','--mount','type=volume,src='+config_volume+',dst=/out','--mount','type=bind,src='+temp+',dst=/fixture,readonly','--entrypoint','bash',host.MONGO_IMAGE,'-c','cp /fixture/service.json /out/service.json && chown 65532:65532 /out/service.json && chmod 400 /out/service.json')
    docker('start',identity);healthy()
    docker('exec',identity,'/app/identity','preflight')
    admin_node=node.replace('REGISTER','false').replace("const claims=JSON.parse", "const summary=JSON.parse((await call('/api/identity/admin/accounts',{after:'',limit:20},central,cookie,null,200)).body); assert(summary.accessHistoryAvailable && summary.accounts.some(a=>a.name==='stack_player' && a.accessHistory.some(h=>h.application==='chronicles')));\nconst claims=JSON.parse")
    self.assertIn('REAL_IMAGE_ACCOUNT_SESSION_AND_REVOCATION_OK',shell(admin_node))
    # Capture an actual active session in an encrypted snapshot, revoke it,
    # then restore into an empty disposable database. Restoration must not
    # resurrect that cookie/JWT or the account's old password.
    keep=node.replace('REGISTER','false').replace("await call('/api/identity/logout',{},origin,cookie,null,204);\nawait call('/api/identity/freshness',proof,null,null,credential,401);", "print('FIXTURE_PROOF='+JSON.stringify({cookie,proof}));")
    proof_output=shell(keep)
    saved=json.loads(next(line[len('FIXTURE_PROOF='):] for line in proof_output.splitlines() if line.startswith('FIXTURE_PROOF=')))
    # Disposable Atlas-style principal: read only the five snapshot collections.
    backup_password=secrets.token_hex(24)
    role_setup='const admin=db.getSiblingDB("admin"); admin.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+');\n'
    role_setup+='const stage=db.getSiblingDB("shadowops_identity_staging"); const resources='+json.dumps(sorted(backup.COLLECTIONS))+';\n'
    role_setup+='admin.createRole({role:"fixture_atlas_backup",roles:[],privileges:resources.map(c=>({resource:{db:"shadowops_identity_staging",collection:c},actions:["find"]}))});\n'
    role_setup+='admin.createUser({user:"fixture_atlas_backup",pwd:'+json.dumps(backup_password)+',roles:[{role:"fixture_atlas_backup",db:"admin"}]});'
    shell(role_setup)
    restore_password=secrets.token_hex(24)
    restore_setup='const admin=db.getSiblingDB("admin"); admin.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+');\n'
    restore_setup+='const names='+json.dumps(sorted(backup.COLLECTIONS))+'; const writeNames=["pending_accounts","admin_inventory_audit","staging_application_access_history"];\n'
    restore_setup+='admin.createRole({role:"fixture_atlas_restore",roles:[],privileges:names.map(c=>({resource:{db:"shadowops_identity_staging",collection:c},actions:writeNames.includes(c)?["find","insert"]:["find"]}))});\n'
    restore_setup+='admin.createUser({user:"fixture_atlas_restore",pwd:'+json.dumps(restore_password)+',roles:[{role:"fixture_atlas_restore",db:"admin"}]});'
    shell(restore_setup)
    atlas_snapshot=json.loads(shell(backup.atlas_export_script('fixture_atlas_backup',backup_password)))
    backup.validate_snapshot(atlas_snapshot)
    with self.assertRaises(AssertionError):shell(backup.atlas_export_script('fixture_atlas_backup','wrong-password-0000000000'))
    snapshot=json.loads(shell(backup.export_script(bundle['mongo_root_password'])))
    self.assertEqual(atlas_snapshot,snapshot)
    self.assertEqual(snapshot['schema'],2)
    self.assertEqual(len(snapshot['collections']['staging_application_access_history']),1)
    self.assertEqual(len(snapshot['collections']['admin_inventory_audit']),1)
    encrypted=backup.encrypt_snapshot(snapshot,bundle['backup_key'])
    restored=backup.decrypt_snapshot(encrypted,bundle['backup_key'])
    prefix=node.split('if (REGISTER)')[0]
    ending="})().catch(error => { print('REAL_IMAGE_REQUEST_FAILED ' + error.message); quit(1); });"
    shell(prefix+"await call('/api/identity/logout',{},origin,"+json.dumps(saved['cookie'])+",null,204);\n"+ending)
    with self.assertRaises(AssertionError):shell(backup.restore_script(bundle['mongo_root_password'],restored))
    unchanged=json.loads(shell(backup.export_script(bundle['mongo_root_password'])))
    self.assertEqual(unchanged['collections']['pending_accounts'],snapshot['collections']['pending_accounts'])
    docker('stop',identity)
    # Only this test's newly created private Mongo is modified; no host port exists.
    shell('const a=db.getSiblingDB("admin"); a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); for (const c of ["pending_accounts","sessions","staging_cka_tokens"]) db.getSiblingDB("shadowops_identity_staging").getCollection(c).deleteMany({});')
    with self.assertRaises(AssertionError):shell(backup.restore_script(bundle['mongo_root_password'],restored))
    shell('const a=db.getSiblingDB("admin"); a.auth("identity_root",'+json.dumps(bundle['mongo_root_password'])+'); for (const c of ["admin_inventory_audit","staging_application_access_history"]) db.getSiblingDB("shadowops_identity_staging").getCollection(c).deleteMany({});')
    with self.assertRaises(AssertionError):shell(backup.atlas_restore_script('fixture_atlas_backup',backup_password,restored))
    self.assertIn('IDENTITY_STAGING_QUARANTINE_RESTORE_OK',shell(backup.atlas_restore_script('fixture_atlas_restore',restore_password,restored)))
    after_restore=json.loads(shell(backup.export_script(bundle['mongo_root_password'])))
    self.assertEqual(after_restore['collections']['pending_accounts'][0]['role'],'user')
    for name in ('staging_application_access_history','admin_inventory_audit'):
     self.assertEqual(after_restore['collections'][name],snapshot['collections'][name])
    docker('start',identity);healthy()
    shell(prefix+"await call('/api/identity/login',credentials,central,null,null,401);\n"+
        "await call('/api/identity/token',{},origin,"+json.dumps(saved['cookie'])+",null,401);\n"+
        "await call('/api/identity/freshness',"+json.dumps(saved['proof'])+",null,null,credential,401);\n"+ending)
    self.assertEqual(json.loads(docker('inspect','--format','{{json .HostConfig.PortBindings}}',mongo)),{})
    self.assertEqual(json.loads(docker('inspect','--format','{{json .HostConfig.PortBindings}}',identity)),{})
  finally:
   for container in reversed(containers):quiet('rm','-f','-v',container)
   for volume in volumes:quiet('volume','rm',volume)
   if network_created:quiet('network','rm',network)
   if image_created:quiet('image','rm',image)


if __name__=='__main__':unittest.main()
