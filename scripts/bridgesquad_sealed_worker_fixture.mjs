#!/usr/bin/env node
// Disposable Node 22 bridge: executes the EXACT sealed Cloudflare _worker.js
// and HTML with synthetic Ed25519 JWT and live-freshness replies.
// Only binds 127.0.0.1; NEVER connects to Cloudflare or public Identity.
import {createServer} from 'node:http';
import {readFileSync,readdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash,webcrypto} from 'node:crypto';

const DIR=resolve(process.argv[2]||'');
const HOST='bridgesquad.shadowops.dpdns.org';
const ID='https://id.shadowops.dpdns.org';
const SITE='https://'+HOST;
const PROOF='soc1_'+'S'.repeat(43);
const SUBJECT_A='123e4567-e89b-42d3-a456-426614174000';
const SUBJECT_B='123e4567-e89b-42d3-a456-426614174001';

function requireCondition(ok,message){if(!ok)throw Error(message);}
requireCondition(process.argv.length===3,'one sealed directory required');
requireCondition(JSON.stringify(readdirSync(DIR).sort())===
  JSON.stringify(['_worker.js','index.html','release.json']),'unexpected sealed files');
const html=readFileSync(join(DIR,'index.html'));
const edge=readFileSync(join(DIR,'_worker.js'));
const manifest=JSON.parse(readFileSync(join(DIR,'release.json'),'utf8'));
const sha=b=>createHash('sha256').update(b).digest('hex');
requireCondition(manifest?.authentication?.required===true &&
  manifest?.authentication?.audience==='bridgesquad' &&
  manifest?.environment==='production' &&
  manifest?.files?.['index.html']?.sha256===sha(html) &&
  manifest?.files?.['_worker.js']?.sha256===sha(edge),
  'sealed bundle digest or authentication policy mismatch');
const module=await import('data:text/javascript;base64,'+edge.toString('base64'));
requireCondition(typeof module.handle==='function','sealed Worker handler missing');

const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
const publicJwk=await webcrypto.subtle.exportKey('jwk',pair.publicKey);
const jwk={...publicJwk,kid:'synthetic-sealed-browser-key',use:'sig',alg:'EdDSA'};
let tokenSubject=SUBJECT_A,accountActive=true,appAssetsServed=0;
const now=()=>Math.floor(Date.now()/1000);
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
async function sign(){
  const claims={iss:ID,aud:'bridgesquad',sub:tokenSubject,sv:1,jti:'sealed-browser-fixture',
    iat:now()-1,nbf:now()-1,exp:now()+116};
  const message=encode({alg:'EdDSA',kid:jwk.kid})+'.'+encode(claims);
  const signature=Buffer.from(await webcrypto.subtle.sign('Ed25519',pair.privateKey,
    new TextEncoder().encode(message))).toString('base64url');
  return message+'.'+signature;
}
async function identityFetch(url,options){
  if(url===ID+'/api/identity/jwks')return Response.json({keys:[jwk]});
  if(url===ID+'/api/identity/freshness'){
    requireCondition(options?.headers?.Authorization==='Bearer '+PROOF,'wrong service proof');
    const body=JSON.parse(options.body);
    return Response.json({issuer:ID,audience:'bridgesquad',subject:body.subject,
      session_version:body.session_version,token_jti:body.token_jti,
      account_active:accountActive,session_active:accountActive,
      token_active:accountActive,checked_at:now()});
  }
  throw Error('unexpected synthetic Identity route');
}
const env={SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL:PROOF,
  ASSETS:{fetch:async request=>{
    appAssetsServed++;
    const path=new URL(request.url).pathname;
    if(path==='/'||path==='/index.html')
      return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8'}});
    if(path==='/release.json')
      return Response.json(manifest);
    return new Response('Not found',{status:404});
  }}
};
const cors={'Access-Control-Allow-Origin':SITE,'Access-Control-Allow-Credentials':'true',
  'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type'};
function identityResponse(message){
  const parsed=new URL(message.url);
  if(parsed.origin!==ID || parsed.pathname!=='/api/identity/token')
    return new Response('Not found',{status:404,headers:cors});
  if(message.method==='OPTIONS')
    return new Response(null,{status:204,headers:cors});
  if(message.method!=='POST'||!accountActive||
      !(message.headers.cookie||'').includes('__Host-shadowops-id=synthetic'))
    return Response.json({error:'authentication_required'},{status:401,headers:cors});
  return null;
}
async function respond(message){
  const parsed=new URL(message.url);
  if(parsed.origin===ID){
    const early=identityResponse(message);
    if(early)return early;
    return Response.json({token:await sign()},{headers:cors});
  }
  // Includes Pages aliases: the REAL worker must refuse their host.
  const url=parsed.toString();
  const method=message.method;
  const body=message.body?Buffer.from(message.body,'base64'):undefined;
  const headers=new Headers(message.headers);
  headers.delete('host');
  const init={method,headers};
  if(body?.length && method!=='GET'&&method!=='HEAD')init.body=body;
  return module.handle(new Request(url,init),env,{request:identityFetch,now:now(),
    subtle:webcrypto.subtle});
}
async function readBody(req){
  const chunks=[];let bytes=0;
  for await(const chunk of req){bytes+=chunk.length;if(bytes>65536)throw Error('bridge request too large');chunks.push(chunk);}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
const server=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json');
  try{
    requireCondition(req.method==='POST','bridge supports POST only');
    const payload=await readBody(req);
    if(req.url==='/control'){
      requireCondition(['revoke','restore','switch','reset','stats'].includes(payload.action),
        'unknown fixture control');
      if(payload.action==='revoke')accountActive=false;
      if(payload.action==='restore')accountActive=true;
      if(payload.action==='switch')tokenSubject=SUBJECT_B;
      if(payload.action==='reset'){tokenSubject=SUBJECT_A;accountActive=true;}
      res.end(JSON.stringify({active:accountActive,assets:appAssetsServed}));
      return;
    }
    requireCondition(req.url==='/request','foreign bridge endpoint');
    const response=await respond(payload);
    const responseBody=Buffer.from(await response.arrayBuffer());
    requireCondition(responseBody.length<=2_000_000,'bridge response oversized');
    const headers=Object.fromEntries(response.headers);
    res.end(JSON.stringify({status:response.status,headers,
      body:responseBody.toString('base64')}));
  }catch(error){
    // Synthetic errors must be visible to CI; no real credentials exist.
    res.statusCode=500;
    res.end(JSON.stringify({error:String(error?.message||error)}));
  }
});
server.listen(0,'127.0.0.1',()=>{
  process.stdout.write(JSON.stringify({fixture_port:server.address().port})+'\n');
});
