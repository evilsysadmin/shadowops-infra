import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {Miniflare} from 'miniflare';

const HOST='https://staging.pawnaction.shadowops.dpdns.org';
const ISSUER='https://id-staging.shadowops.dpdns.org';
const REVISION='a1b2c3d4e5f60718';
const COOKIE='__Host-pawnaction_staging';
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
test('workerd: private R2-only delivery rejects anonymous, lets signed session stream wasm, denies after revocation',async t=>{
 const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk={...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid:'private-r2-fixture',use:'sig',alg:'EdDSA'};
 const now=Math.floor(Date.now()/1000);
 const claims={iss:ISSUER,aud:'pawn-action',sub:'11111111-1111-4111-8111-111111111111',
  iat:now,nbf:now,exp:now+120,sv:1,jti:Buffer.alloc(16,13).toString('base64url')};
 const unsigned=encode({alg:'EdDSA',typ:'JWT',kid:jwk.kid})+'.'+encode(claims);
 const token=unsigned+'.'+Buffer.from(await webcrypto.subtle.sign('Ed25519',pair.privateKey,Buffer.from(unsigned))).toString('base64url');
 const proof='soc1_'+Buffer.alloc(32,6).toString('base64url');
 let live=true,idpCalls=0;
 const mf=new Miniflare({
  cf:false,modules:true,compatibilityDate:'2026-07-30',
  scriptPath:'tests/fixtures/pawn_action_private_delivery_workerd.mjs',
  bindings:{SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL:proof,PAWN_ACTION_PRIVATE_RELEASE:REVISION},
  r2Buckets:{PAWN_ACTION_PRIVATE_R2:'private-staging-fixture'},
  serviceBindings:{
   async SYNTHETIC_IDENTITY(req){
    idpCalls++;
    if(req.url===ISSUER+'/api/identity/jwks')return Response.json({keys:[jwk]});
    if(req.url===ISSUER+'/api/identity/freshness'){
     assert.equal(req.headers.get('Authorization'),'Bearer '+proof);
     const p=await req.json();
     if(!live)return new Response('',{status:401});
     return Response.json({issuer:ISSUER,audience:'pawn-action',subject:p.subject,
      session_version:p.session_version,token_jti:p.token_jti,checked_at:now,
      account_active:true,session_active:true,token_active:true});
    }
    throw Error('Test attempted unexpected upstream');
   },
  },
 });
 t.after(()=>mf.dispose());
 const bucket=await mf.getR2Bucket('PAWN_ACTION_PRIVATE_R2');
 // This is deliberately >25 MiB: it cannot be hosted by Pages directly.
 const payload=new Uint8Array(25*1024*1024+101);
 payload.set([0,97,115,109]);payload[payload.length-1]=23;
 await bucket.put('pawn-action/releases/'+REVISION+'/index.wasm',payload);
 await bucket.put('pawn-action/releases/'+REVISION+'/index.html','<html>PRIVATE GODOT</html>');
 const no=await mf.dispatchFetch(HOST+'/index.wasm');
 assert.equal(no.status,401);assert.equal(idpCalls,0);
 const encodedCookie=COOKIE+'='+token;
 const yes=await mf.dispatchFetch(HOST+'/index.wasm',{headers:{Cookie:encodedCookie}});
 assert.equal(yes.status,200);
 assert.equal(yes.headers.get('Content-Type'),'application/wasm');
 assert.equal(yes.headers.get('Cross-Origin-Embedder-Policy'),'require-corp');
 assert.equal(yes.headers.get('Cross-Origin-Resource-Policy'),'same-origin');
 assert.equal(yes.headers.get('Content-Length'),null);
 const received=new Uint8Array(await yes.arrayBuffer());
 assert.equal(received.length,payload.byteLength);
 assert.equal(received[0],0);assert.equal(received[received.length-1],23);
 assert.equal(idpCalls,2);
 const html=await mf.dispatchFetch(HOST+'/',{headers:{Cookie:encodedCookie}});
 assert.equal(html.status,200);assert.match(await html.text(),/PRIVATE GODOT/);
 assert.equal(idpCalls,4);
 const head=await mf.dispatchFetch(HOST+'/index.wasm',{method:'HEAD',headers:{Cookie:encodedCookie}});
 assert.equal(head.status,200);assert.equal(await head.text(),'');
 assert.equal(idpCalls,6);
 const bad=await mf.dispatchFetch('https://assets.chess-studio.shadowops.dpdns.org/pawn-action/releases/'+REVISION+'/index.wasm');
 assert.equal(bad.status,404);assert.equal(idpCalls,6);
 live=false;
 const revoked=await mf.dispatchFetch(HOST+'/index.wasm',{headers:{Cookie:encodedCookie}});
 assert.equal(revoked.status,401);assert.equal(idpCalls,8);
});
test('workerd: session exchange enforces CSRF before private access; disabled R2 binding fails closed',async t=>{
 const mf=new Miniflare({cf:false,modules:true,compatibilityDate:'2026-07-30',
  scriptPath:'workers/pawn-action-staging/private-delivery.mjs',
  bindings:{PAWN_ACTION_PRIVATE_RELEASE:REVISION}});
 t.after(()=>mf.dispose());
 const anon=await mf.dispatchFetch(HOST+'/index.pck');
 assert.equal(anon.status,401,'anonymous access must never reach R2');
 const csrf=await mf.dispatchFetch(HOST+'/api/pawn-action/session',{
  method:'POST',headers:{Origin:'https://staging.football.shadowops.dpdns.org','Content-Type':'application/json'},
  body:'{"token":"fake"}',
 });
 assert.equal(csrf.status,403);assert.equal(csrf.headers.get('Set-Cookie'),null);
 const unsupported=await mf.dispatchFetch(HOST+'/release.json');
 assert.equal(unsupported.status,404);
});
