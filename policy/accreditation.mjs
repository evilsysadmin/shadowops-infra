import { admitCandidate } from './chronicles.mjs';
// Must correspond to the published image workflow checked by github-evidence.
const TRUSTED_WORKFLOW = '.github/workflows/staging-image.yml';
export function accredit(candidate, context, evidence) {
  const admitted = admitCandidate(candidate, context);
  if (!evidence || typeof evidence !== 'object') throw new Error('missing evidence');
  if (evidence.repository !== admitted.repository || evidence.sha !== admitted.sha) throw new Error('source provenance mismatch');
  if (evidence.workflow !== TRUSTED_WORKFLOW || evidence.conclusion !== 'success' || evidence.event !== 'push' || evidence.ref !== 'refs/heads/main') throw new Error('untrusted build workflow');
  if (evidence.imageDigest !== admitted.digest) throw new Error('digest not linked to build');
  if (evidence.attestationVerified !== true) throw new Error('image attestation unverified');
  if (evidence.requiredChecksPassed !== true) throw new Error('required checks missing');
  return Object.freeze({ repository: admitted.repository, service: admitted.service, sha: admitted.sha, digest: admitted.digest, environment: admitted.environment, workflowRunId: evidence.runId });
}
