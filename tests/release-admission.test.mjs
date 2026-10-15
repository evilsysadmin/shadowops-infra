import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateRelease} from '../policy/release-admission.mjs';
const sha='a'.repeat(40),digest='sha256:'+'b'.repeat(64);
const candidate={repository:'evilsysadmin/chronicles-of-matthias',service:'chronicles-api',sha,digest,environment:'staging'};
const context={event:'repository_dispatch',actorRepository:candidate.repository};
const run={workflow_id:386009048,repository:{full_name:'evilsysadmin/chronicles-of-matthias'},head_sha:sha,event:'push',head_branch:'main',status:'completed',conclusion:'success',path:'.github/workflows/staging-image.yml'};
const statement={predicateType:'https://slsa.dev/provenance/v1',subject:[{digest:{sha256:'b'.repeat(64)}}],predicate:{buildDefinition:{externalParameters:{workflow:{repository:'https://github.com/evilsysadmin/chronicles-of-matthias'}},resolvedDependencies:[{digest:{gitCommit:sha}}]}}};
const attestationRunner=()=>({status:0,stdout:JSON.stringify([{verificationResult:{statement}}])});
function fetchImpl(url) {
 const path=new URL(url).pathname;
 const body=path.endsWith('/actions/runs/12')?run:path.endsWith('/commits/'+sha)?{sha}:path.endsWith('/branches/main')?{protected:true}:path.endsWith('/compare/'+sha+'...main')?{status:'identical',behind_by:0}:path.endsWith('/check-runs')?{total_count:1,check_runs:[{name:'tests',head_sha:sha,status:'completed',conclusion:'success'}]}:null;
 return Promise.resolve({ok:!!body,json:async()=>body});
}
const input={candidate,context,runId:12,token:'test',requiredContexts:['tests'],fetchImpl,attestationRunner};
test('orchestrates independent gates without deploying',async()=>assert.equal((await evaluateRelease(input)).digest,digest));
test('fails closed on bad attestation, checks or candidate',async()=>{
 await assert.rejects(evaluateRelease({...input,attestationRunner:()=>({status:1,stdout:''})}));
 await assert.rejects(evaluateRelease({...input,requiredContexts:['missing']}));
 await assert.rejects(evaluateRelease({...input,candidate:{...candidate,environment:'production'}}));
});
