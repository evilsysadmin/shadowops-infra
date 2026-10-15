import test from 'node:test';
import assert from 'node:assert/strict';
import {attestationCommand, verifyImage} from '../scripts/verify-image-attestation.mjs';

const sha = 'a'.repeat(40);
const digest = 'sha256:' + 'b'.repeat(64);
const verified = {
  verificationResult: {
    statement: {
      predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{digest: {sha256: 'b'.repeat(64)}}],
      // Statement metadata is informational. Source SHA and workflow identity
      // MUST be checked by the signed-certificate CLI flags.
      predicate: {}
    }
  }
};
const runner = output => () => ({status: 0, stdout: JSON.stringify(output)});

test('verifies OCI digest against fixed signing workflow and signed source SHA', () => {
  assert.deepEqual(attestationCommand({sha, digest}), [
    'attestation','verify',
    'oci://ghcr.io/evilsysadmin/chronicles-api@' + digest,
    '--repo','evilsysadmin/chronicles-of-matthias',
    '--signer-workflow','evilsysadmin/chronicles-of-matthias/.github/workflows/staging-image.yml',
    '--source-digest',sha,
    '--source-ref','refs/heads/main',
    '--predicate-type','https://slsa.dev/provenance/v1',
    '--format','json'
  ]);
});

test('only accepts successful verifier output for the exact image and predicate type', () => {
  assert.equal(verifyImage({sha,digest,runner:runner([verified])}).verified,true);
  for (const records of [
    [],
    [{verificationResult:{statement:{...verified.verificationResult.statement,subject:[]}}}],
    [{verificationResult:{statement:{...verified.verificationResult.statement,predicateType:'https://example.org/predicate'}}}],
    [{verificationResult:{statement:{...verified.verificationResult.statement,subject:[{digest:{sha256:'c'.repeat(64)}}]}}}],
    [{verificationResult:{statement:null}}],
  ]) assert.throws(()=>verifyImage({sha,digest,runner:runner(records)}));
  assert.throws(()=>verifyImage({sha,digest,runner:()=>({status:1,stdout:''})}));
  assert.throws(()=>verifyImage({sha,digest,runner:()=>({status:0,stdout:'not json'})}));
  assert.throws(()=>attestationCommand({sha:'main',digest}));
  assert.throws(()=>attestationCommand({sha,digest:'sha256:abcd'}));
});

test('does not trust user-reported workflow identity in unsigned predicates', () => {
  const malicious = {
    verificationResult: {
      statement: {
        ...verified.verificationResult.statement,
        predicate: {buildDefinition: {externalParameters: {
          workflow: {repository: 'https://github.com/evilsysadmin/chronicles-of-matthias'}
        }}}
      }
    }
  };
  let observed;
  const result=verifyImage({sha,digest,runner:(program,args)=>{
    observed={program,args};
    return {status:0,stdout:JSON.stringify([malicious])};
  }});
  assert.equal(result.verified,true);
  assert.equal(observed.program,'gh');
  assert.ok(observed.args.includes('--signer-workflow'));
  assert.ok(observed.args.includes('--source-digest'));
});
