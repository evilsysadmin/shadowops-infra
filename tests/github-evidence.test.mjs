import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyGithubBuild } from '../policy/github-evidence.mjs';
const sha = 'a'.repeat(40), runId = 123;
const run = {workflow_id:386009048,repository:{full_name:'evilsysadmin/chronicles-of-matthias'},head_sha:sha,event:'push',head_branch:'main',status:'completed',conclusion:'success',path:'.github/workflows/staging-image.yml'};
const fixtures = {'/actions/runs/123':run,['/commits/'+sha]:{sha},'/branches/main':{protected:true},['/compare/'+sha+'...main']:{status:'identical',behind_by:0}};
function mock(values=fixtures) {return async url => {const path = new URL(url).pathname.split('/chronicles-of-matthias')[1]; return {ok:true,json:async()=>values[path]};};}
test('verifies run, commit and protected branch independently',async()=>assert.equal((await verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock()})).runId,runId));
test('rejects bad run, SHA and branch policy',async()=>{
 for (const [field,value] of [['head_sha','b'.repeat(40)],['event','pull_request'],['head_branch','dev'],['conclusion','failure'],['path','other.yml'],['workflow_id',1],['repository',{full_name:'another/repo'}]]) {
  await assert.rejects(verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,'/actions/runs/123':{...run,[field]:value}})}),field);
 }
 await assert.rejects(verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,'/branches/main':{protected:false}})}));
 await assert.rejects(verifyGithubBuild({sha,runId,token:''}));
 for(const lineage of [{status:'diverged',behind_by:1},{status:'behind',behind_by:2},{status:'ahead',behind_by:1}]){
  await assert.rejects(verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,['/compare/'+sha+'...main']:lineage})}),'lineage');
 }
 const older=await verifyGithubBuild({sha,runId,token:'test',fetchImpl:mock({...fixtures,['/compare/'+sha+'...main']:{status:'ahead',behind_by:0}})});
 assert.equal(older.sha,sha);
});
