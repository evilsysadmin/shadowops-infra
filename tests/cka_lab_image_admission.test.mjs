import test from 'node:test';
import assert from 'node:assert/strict';
import {SOURCE, IMAGE, SIGNER, REQUIRED, attestArgs, verifyAttestation,
  verifyManifest, verifySourceRuns, validateInput, admit} from '../scripts/cka_lab_image_admission.mjs';

const SHA = 'a'.repeat(40);
const DIGEST = 'sha256:' + 'b'.repeat(64);
const PLAT = n => ({digest:'sha256:'+n.repeat(64),platform:{os:'linux',architecture:n==='c'?'arm64':'amd64'}});
const MANIFEST = {schemaVersion:2,manifests:[PLAT('c'),PLAT('d'),
  {digest:'sha256:'+'e'.repeat(64),platform:{os:'unknown',architecture:'unknown'}}]};
const ATT = [{verificationResult:{statement:{predicateType:'https://slsa.dev/provenance/v1',
  subject:[{digest:{sha256:DIGEST.slice(7)}}]}}}];
const RUNS = {workflow_runs:REQUIRED.map((name,i)=>({
  name,head_sha:SHA,head_branch:'main',event:'push',status:'completed',
  conclusion:'success',repository:{full_name:SOURCE},id:i+1
}))};

test('strict immutable source, OCI digest and signer workflow',()=>{
  assert.deepEqual(attestArgs(SHA,DIGEST),[
    'attestation','verify','oci://'+IMAGE+'@'+DIGEST,'--repo',SOURCE,
    '--signer-workflow',SIGNER,'--source-digest',SHA,
    '--source-ref','refs/heads/main','--predicate-type','https://slsa.dev/provenance/v1',
    '--format','json'
  ]);
  for (const [sha,digest] of [['main',DIGEST],[SHA,'latest'],[SHA,'sha256:ABC'],
    ['A'.repeat(40),DIGEST],[SHA,DIGEST+'x']]) {
    assert.throws(()=>validateInput(sha,digest));
  }
});
test('only exact A1 arm64 and amd64 manifests allowed',()=>{
  assert.doesNotThrow(()=>verifyManifest(MANIFEST));
  for (const value of [null,{schemaVersion:1,manifests:MANIFEST.manifests},
    {schemaVersion:2,manifests:[]},
    {schemaVersion:2,manifests:[PLAT('c'),PLAT('c')]},
    {schemaVersion:2,manifests:[PLAT('c'),PLAT('d'),PLAT('d')]},
    {schemaVersion:2,manifests:[{...PLAT('c'),digest:'latest'},PLAT('d')]}]) {
    assert.throws(()=>verifyManifest(value));
  }
});
test('signed subject must match exact image digest and SLSA predicate',()=>{
  verifyAttestation(ATT,DIGEST);
  for(const bad of [[],[{}],[{verificationResult:{statement:{...ATT[0].verificationResult.statement,subject:[]}}}],
    [{verificationResult:{statement:{...ATT[0].verificationResult.statement,predicateType:'other'}}}]]) {
    assert.throws(()=>verifyAttestation(bad,DIGEST));
  }
  assert.throws(()=>verifyAttestation(ATT,'sha256:'+'0'.repeat(64)));
});
test('require protected source main and all four successful push workflows',()=>{
  verifySourceRuns({sha:SHA},RUNS,SHA);
  assert.throws(()=>verifySourceRuns({sha:'c'.repeat(40)},RUNS,SHA));
  for(const edited of [
    {...RUNS,workflow_runs:RUNS.workflow_runs.slice(1)},
    {...RUNS,workflow_runs:RUNS.workflow_runs.map((x,i)=>i===0?{...x,event:'pull_request'}:x)},
    {...RUNS,workflow_runs:RUNS.workflow_runs.map((x,i)=>i===0?{...x,conclusion:'skipped'}:x)},
    {...RUNS,workflow_runs:RUNS.workflow_runs.map((x,i)=>i===0?{...x,head_branch:'release'}:x)},
    {...RUNS,workflow_runs:RUNS.workflow_runs.map((x,i)=>i===0?{...x,head_sha:'c'.repeat(40)}:x)},
    {...RUNS,workflow_runs:RUNS.workflow_runs.map((x,i)=>i===0?{...x,repository:{full_name:'attacker/cka'}}:x)}
  ]) assert.throws(()=>verifySourceRuns({sha:SHA},edited,SHA));
});
test('admission only verifies 4 fixed read-only commands, never deploys',()=>{
  const calls=[];
  const runner=(tool,args)=>{
    calls.push({tool,args});
    const raw=calls.length===1?{sha:SHA}:calls.length===2?RUNS:
      calls.length===3?MANIFEST:ATT;
    return {status:0,stdout:JSON.stringify(raw)};
  };
  const result=admit(SHA,DIGEST,runner);
  assert.deepEqual(result,{source_sha:SHA,image_digest:DIGEST,source_checks:4,
    signed_provenance:true,arm64:true,amd64:true,deployment_performed:false});
  assert.deepEqual(calls.map(x=>x.tool),['gh','gh','docker','gh']);
  assert.ok(calls.every(({args})=>!args.some(s=>['run','apply','install','up','start','login','push'].includes(s))));
  for(let fail=1;fail<=4;fail++){
    let n=0;
    assert.throws(()=>admit(SHA,DIGEST,(tool,args)=>{
      n++;
      if(n===fail)return{status:1,stdout:'secret'};
      return {status:0,stdout:JSON.stringify(n===1?{sha:SHA}:n===2?RUNS:n===3?MANIFEST:ATT)};
    }));
    assert.equal(n,fail);
  }
});
