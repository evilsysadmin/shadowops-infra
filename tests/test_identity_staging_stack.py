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
from identity_staging_bundle import generate,service_config
import identity_staging_backup as backup
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

 def test_private_tls_image_account_revocation_and_database_persistence(self):
  prefix='identity-stack-test-'+secrets.token_hex(5)
  network=prefix+'-network'; mongo=prefix+'-mongo'; identity=prefix+'-service'
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
    # Capture an actual active session in an encrypted snapshot, revoke it,
    # then restore into an empty disposable database. Restoration must not
    # resurrect that cookie/JWT or the account's old password.
    keep=node.replace('REGISTER','false').replace("await call('/api/identity/logout',{},origin,cookie,null,204);\nawait call('/api/identity/freshness',proof,null,null,credential,401);", "print('FIXTURE_PROOF='+JSON.stringify({cookie,proof}));")
    proof_output=shell(keep)
    saved=json.loads(next(line[len('FIXTURE_PROOF='):] for line in proof_output.splitlines() if line.startswith('FIXTURE_PROOF=')))
    snapshot=json.loads(shell(backup.export_script(bundle['mongo_root_password'])))
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
    self.assertIn('IDENTITY_STAGING_QUARANTINE_RESTORE_OK',shell(backup.restore_script(bundle['mongo_root_password'],restored)))
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
