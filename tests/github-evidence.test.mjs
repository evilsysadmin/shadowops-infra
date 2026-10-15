import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyGithubBuild } from '../policy/github-evidence.mjs';
const sha = 'a'.repeat(40), runId = 123;
const run = {head_sha:sha,event:'push',head_branch:'main',status:'completed',conclusion:'success',path:'.github/workflows/publish-chronicles.yml'};
const fixtures = {'/actions/runs/123':run,['/commits/'+sha]:{sha},'/branches/main':{protected:true}};
function mock(values=fixtures) {return async url => {const path = new URL(url).pathname.split('/chronicles-of-matthias')[1]; return {ok:true,json:async()=>values[path]};};}
test('verifies run, commit and protected branch independently',async()=>assert.equal((await verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock()})).runId,runId));
test('rejects bad run, SHA and branch policy',async()=>{
 for (const [field,value] of [['head_sha','b'.repeat(40)],['event','pull_request'],['head_branch','dev'],['conclusion','failure'],['path','other.yml']]) {
  await assert.rejects(verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,'/actions/runs/123':{...run,[field]:value}})}),field);
 }
 await assert.rejects(verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,'/branches/main':{protected:false}})}));
 await assert.rejects(verifyGithubBuild({sha,runId,token:''}));
});
