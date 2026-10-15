import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { parseCandidateArgs, inspectCandidate } from '../scripts/check-staging-candidate.mjs';

const sha='a'.repeat(40);
const digest='sha256:'+'b'.repeat(64);
const args=['--sha',sha,'--digest',digest,'--run-id','38808611625'];

test('only accepts immutable SHA, image digest and positive source workflow run',()=>{
 const parsed=parseCandidateArgs(args);
 assert.equal(parsed.candidate.sha,sha);
 assert.equal(parsed.candidate.digest,digest);
 assert.equal(parsed.candidate.repository,'evilsysadmin/chronicles-of-matthias');
 assert.equal(parsed.candidate.environment,'staging');
 assert.equal(parsed.runId,38808611625);
 for (const bad of [
   [],
   ['--sha','main','--digest',digest,'--run-id','38808611625'],
   ['--sha',sha,'--digest','sha256:bad','--run-id','38808611625'],
   ['--sha',sha,'--digest',digest,'--run-id','0'],
   ['--sha',sha,'--digest',digest,'--run-id','9007199254740999'],
   ['--sha',sha,'--digest',digest,'--run-id','1','--environment','production'],
   ['--sha',sha,'--digest',digest,'--run-id','1','--sha',sha],
 ]) assert.throws(()=>parseCandidateArgs(bad));
});

test('passes fixed source identity and never caller-provided checks to admission',async()=>{
 let observed;
 const result=await inspectCandidate({
  argv:args,token:'read-only-token',
  evaluator: async input=>{
   observed=input;
   return {sha,digest,workflowRunId:input.runId};
  }
 });
 assert.equal(result.workflowRunId,38808611625);
 assert.deepEqual(observed.context,{
  event:'repository_dispatch',
  actorRepository:'evilsysadmin/chronicles-of-matthias'
 });
 assert.equal(observed.requiredContexts,undefined);
 assert.equal(observed.candidate.service,'chronicles-api');
 assert.equal(observed.candidate.environment,'staging');
});

test('missing credentials and failed admission never produce success',async()=>{
 await assert.rejects(inspectCandidate({argv:args,token:''}));
 await assert.rejects(inspectCandidate({
  argv:args,token:'token',
  evaluator:async()=>{throw new Error('main branch not protected')}
 }),/main branch not protected/);
 const command=spawnSync(process.execPath,[
  'scripts/check-staging-candidate.mjs',...args
 ],{encoding:'utf8',env:{...process.env,GH_TOKEN:''},timeout:5000});
 assert.equal(command.status,1);
 assert.match(command.stderr,/STAGING_CANDIDATE_BLOCKED/);
 assert.doesNotMatch(command.stdout,/STAGING_CANDIDATE_ACCREDITED/);
});
