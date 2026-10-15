import { spawnSync } from 'node:child_process';

const REPO = 'evilsysadmin/chronicles-of-matthias';
const IMAGE = 'ghcr.io/evilsysadmin/chronicles-api';
const SIGNER = REPO + '/.github/workflows/staging-image.yml';
const REF = 'refs/heads/main';
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PROVENANCE = 'https://slsa.dev/provenance/v1';

// Enforce signed certificate provenance in gh's verifier. Do not rely solely
// on unsigned/untrusted statement.predicate metadata supplied by a builder.
export function attestationCommand({sha, digest}) {
  if (!SHA.test(sha || '') || !DIGEST.test(digest || '')) {
    throw new Error('invalid source SHA or image digest');
  }
  return [
    'attestation', 'verify', 'oci://' + IMAGE + '@' + digest,
    '--repo', REPO,
    '--signer-workflow', SIGNER,
    '--source-digest', sha,
    '--source-ref', REF,
    '--predicate-type', PROVENANCE,
    '--format', 'json'
  ];
}

export function verifyImage({sha, digest, runner = spawnSync}) {
  const args = attestationCommand({sha, digest});
  const result = runner('gh', args, {
    encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error('signed GHCR image provenance verification failed');
  }
  let attestations;
  try { attestations = JSON.parse(result.stdout); }
  catch { throw new Error('invalid verified attestation JSON'); }
  if (!Array.isArray(attestations) || attestations.length === 0) {
    throw new Error('missing verified attestations');
  }
  const matching = attestations.some(entry => {
    const statement = entry?.verificationResult?.statement;
    return statement?.predicateType === PROVENANCE &&
      Array.isArray(statement?.subject) &&
      statement.subject.some(subject => subject.digest?.sha256 === digest.slice(7));
  });
  if (!matching) throw new Error('verified subject digest or provenance type differs');
  // The CLI has already verified the signer workflow, source commit/ref,
  // predicate type, and Sigstore identity before returning success.
  return Object.freeze({sha, digest, verified: true});
}
