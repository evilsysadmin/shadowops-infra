import test from 'node:test';
import assert from 'node:assert/strict';
import {TRUSTED_CHECKS,verifyRequiredChecks} from '../policy/required-checks.mjs';

const sha='a'.repeat(40);
const sourceRunId=12;
const job = (name,run=12) => ({
  name, head_sha:sha, status:'completed', conclusion:'success',
  app:{slug:'github-actions'},
  details_url:`https://github.com/evilsysadmin/chronicles-of-matthias/actions/runs/${run}/job/432`,
});
const checks=TRUSTED_CHECKS.map(name=>job(name,sourceRunId));
const mock=data=>async()=>({ok:true,json:async()=>data});
const base={sha,sourceRunId,token:'test'};
const payload=runs=>({total_count:runs.length,check_runs:runs});

test('require all five fixed real-source checks, tied to source workflow',async()=>{
  const observed=await verifyRequiredChecks({...base,fetchImpl:mock(payload(checks))});
  assert.deepEqual(observed.requiredContexts,TRUSTED_CHECKS);
});

test('reject incomplete, failed, duplicate, wrong-app, wrong-SHA and wrong-workflow checks',async()=>{
  const bad=[checks.slice(0,-1),checks.concat(checks[0])];
  for(const list of bad){
    await assert.rejects(verifyRequiredChecks({...base,fetchImpl:mock(payload(list))}));
  }
  for(const patch of [
    {status:'in_progress'},{conclusion:'failure'},
    {head_sha:'b'.repeat(40)},{app:{slug:'random-app'}},
    {details_url:'https://attacker.invalid/verified'},
    {details_url:'https://github.com/evilsysadmin/chronicles-of-matthias/actions/runs/99/job/123'},
  ]){
    const altered=checks.map(x=>x.name==='publish-staging-image'?{...x,...patch}:x);
    await assert.rejects(verifyRequiredChecks({...base,fetchImpl:mock(payload(altered))}));
  }
});

test('reject caller-selected checks, missing verified run, and broken pagination',async()=>{
  await assert.rejects(verifyRequiredChecks({...base,requiredContexts:['smoke'],fetchImpl:mock(payload(checks))}));
  await assert.rejects(verifyRequiredChecks({...base,sourceRunId:0,fetchImpl:mock(payload(checks))}));
  await assert.rejects(verifyRequiredChecks({...base,token:'',fetchImpl:mock(payload(checks))}));
  await assert.rejects(verifyRequiredChecks({...base,fetchImpl:mock({total_count:101,check_runs:checks})}));
  await assert.rejects(verifyRequiredChecks({...base,fetchImpl:mock({total_count:6,check_runs:checks})}));
});
