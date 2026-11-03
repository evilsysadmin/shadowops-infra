import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {Miniflare} from 'miniflare';
const HOST='https://staging.pawnaction.shadowops.dpdns.org';
const ISSUER='https://id-staging.shadowops.dpdns.org';
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
test('real workerd: sign, exchange, CSRF deny and live revocation',async t=>{
 const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk={...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid:'fixture-key',use:'sig',alg:'EdDSA'};
 const now=Math.floor(Date.now()/1000);
 const claims={iss:ISSUER,aud:'pawn-action',sub:'11111111-1111-4111-8111-111111111111',
  iat:now,nbf:now,exp:now+120,sv:1,jti:Buffer.alloc(16,2).toString('base64url')};
 const message=encode({alg:'EdDSA',typ:'JWT',kid:jwk.kid})+'.'+encode(claims);
 const token=message+'.'+Buffer.from(await webcrypto.subtle.sign('Ed25519',pair.privateKey,Buffer.from(message))).toString('base64url');
 const proof='soc1_'+Buffer.alloc(32,3).toString('base64url');
 let active=true,calls=0;
 const mf=new Miniflare({
  cf:false,modules:true,compatibilityDate:'2026-07-30',
  scriptPath:'tests/fixtures/pawn_action_session_workerd.mjs',
  bindings:{SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL:proof},
  serviceBindings:{
   async FAKE_IDP(req){
    calls++;
    if(req.url===ISSUER+'/api/identity/jwks')return Response.json({keys:[jwk]});
    if(req.url===ISSUER+'/api/identity/freshness'){
     assert.equal(req.headers.get('Authorization'),'Bearer '+proof);
     const body=await req.json();
     if(!active)return new Response('',{status:401});
     return Response.json({issuer:ISSUER,audience:'pawn-action',subject:body.subject,
      session_version:body.session_version,token_jti:body.token_jti,checked_at:now,
      account_active:true,session_active:true,token_active:true});
    }
    throw Error('unknown fake identity path');
   },
  },
 });
 t.after(()=>mf.dispose());
 const exchange=(origin=HOST)=>mf.dispatchFetch(HOST+'/api/pawn-action/session',{
  method:'POST',headers:{Origin:origin,'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'},
  body:JSON.stringify({token}),
 });
 const valid=await exchange();
 assert.equal(valid.status,200);
 const cookie=valid.headers.get('Set-Cookie');
 assert.match(cookie,/^__Host-pawnaction_staging=/);
 assert.match(cookie,/; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=\d+$/);
 assert.doesNotMatch(cookie,/Domain=/);
 assert.equal(calls,2);
 const csrf=await exchange('https://staging.football.shadowops.dpdns.org');
 assert.equal(csrf.status,403);assert.equal(csrf.headers.get('Set-Cookie'),null);
 assert.equal(calls,2);
 active=false;
 const revoked=await exchange();
 assert.equal(revoked.status,401);
 assert.equal(revoked.headers.get('Set-Cookie'),null);
 assert.equal(calls,4);
});
test('real workerd: locked Pages shell still rejects WASM and home',async t=>{
 const mf=new Miniflare({cf:false,modules:true,compatibilityDate:'2026-07-30',
  scriptPath:'workers/pawn-action-staging/edge.mjs',
  bindings:{PAWN_ACTION_STAGING_ENABLED:'true'}});
 t.after(()=>mf.dispose());
 const wasm=await mf.dispatchFetch(HOST+'/index.wasm');
 assert.equal(wasm.status,503);
 assert.deepEqual(await wasm.json(),{error:'staging_locked'});
 const home=await mf.dispatchFetch(HOST+'/');
 assert.equal(home.status,503);
 assert.match(await home.text(),/El juego aún no se ha publicado/);
});
