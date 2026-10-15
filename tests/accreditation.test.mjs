import test from 'node:test';
import assert from 'node:assert/strict';
import { accredit } from '../policy/accreditation.mjs';
const candidate = {repository:'evilsysadmin/chronicles-of-matthias',service:'chronicles-api',sha:'a'.repeat(40),digest:'sha256:'+'b'.repeat(64),environment:'staging'};
const context = {event:'repository_dispatch',actorRepository:candidate.repository};
const evidence = {repository:candidate.repository,sha:candidate.sha,workflow:'.github/workflows/publish-chronicles.yml',conclusion:'success',event:'push',ref:'refs/heads/main',imageDigest:candidate.digest,attestationVerified:true,requiredChecksPassed:true,runId:123};
test('accepts fully accredited candidate evidence',()=>assert.equal(accredit(candidate,context,evidence).workflowRunId,123));
test('fails closed on missing or inconsistent provenance',()=>{
 for(const [key,value] of [['repository','evilsysadmin/chess-studio'],['sha','c'.repeat(40)],['workflow','other.yml'],['conclusion','failure'],['event','pull_request'],['ref','refs/heads/feature'],['imageDigest','sha256:'+'c'.repeat(64)],['attestationVerified',false],['requiredChecksPassed',false]]) assert.throws(()=>accredit(candidate,context,{...evidence,[key]:value}),key);
 assert.throws(()=>accredit(candidate,context,undefined));
});
