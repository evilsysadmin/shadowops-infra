import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const workflow=readFileSync('.github/workflows/live-ghcr-attestation.yml','utf8');
test('live release admission uses exact SHA, digest and source run from the proven workflow',()=>{
 assert.match(workflow,/Exercise full release admission against real protected main/);
 assert.match(workflow,/node scripts\/check-staging-candidate\.mjs/);
 for(const flag of ['--sha "$EXPECTED_SHA"','--digest "$EXPECTED_DIGEST"','--run-id "$VERIFIED_RUN_ID"']){
  assert.ok(workflow.includes(flag),flag);
 }
 assert.match(workflow,/GH_TOKEN: \$\{\{ github\.token \}\}/);
 assert.match(workflow,/EXPECTED_SHA: [a-f0-9]{40}/);
 assert.match(workflow,/EXPECTED_DIGEST: sha256:[a-f0-9]{64}/);
 assert.doesNotMatch(workflow,/docker compose up|kubectl apply|oci .*deploy|render\.com/);
});
