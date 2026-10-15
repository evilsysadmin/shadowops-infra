import test from 'node:test';
import assert from 'node:assert/strict';
import {attestationCommand,verifyImage} from '../scripts/verify-image-attestation.mjs';
const sha='a'.repeat(40),digest='sha256:'+'b'.repeat(64);
const valid={verificationResult:{statement:{subject:[{digest:{sha256:'b'.repeat(64)}}],predicate:{buildDefinition:{externalParameters:{workflow:{repository:'https://github.com/evilsysadmin/chronicles-of-matthias'}},resolvedDependencies:[{digest:{gitCommit:sha}}]}}}}};
const runner=payload=>()=>({status:0,stdout:JSON.stringify(payload)});
test('pins GHCR image and expected repo',()=>assert.deepEqual(attestationCommand({sha,digest}),['attestation','verify','ghcr.io/evilsysadmin/chronicles-api@'+digest,'--repo','evilsysadmin/chronicles-of-matthias','--format','json']));
test('rejects unverified, mismatched or absent attestations',()=>{
 assert.equal(verifyImage({sha,digest,runner:runner([valid])}).verified,true);
 for(const data of [[],[{...valid,verificationResult:{statement:{...valid.verificationResult.statement,subject:[]}}}]]) assert.throws(()=>verifyImage({sha,digest,runner:runner(data)}));
 assert.throws(()=>verifyImage({sha,digest,runner:()=>({status:1,stdout:''})}));
 assert.throws(()=>attestationCommand({sha:'main',digest}));
});
