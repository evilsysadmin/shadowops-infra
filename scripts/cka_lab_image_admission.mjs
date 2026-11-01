#!/usr/bin/env node
// Admission-only supply-chain gate for the restricted CKA staging image.
// Never starts a container, writes host configuration or activates an endpoint.
import { spawnSync } from 'node:child_process';

export const SOURCE = 'evilsysadmin/cka-exam-simulator';
export const IMAGE = 'ghcr.io/evilsysadmin/cka-lab-staging';
export const SIGNER = SOURCE + '/.github/workflows/lab-staging.yml';
export const REQUIRED = Object.freeze([
  'CI', 'Go scenario contract', 'CKA restricted lab staging', 'CKA account staging'
]);
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const PROVENANCE = 'https://slsa.dev/provenance/v1';

function invoke(executable, args, runner) {
  const result = runner(executable, args, {
    encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 * 1024
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== 'string'
      || result.stdout.length > 2 * 1024 * 1024) {
    throw new Error('CKA image admission evidence unavailable');
  }
  try { return JSON.parse(result.stdout); }
  catch { throw new Error('CKA image admission evidence malformed'); }
}

export function validateInput(sha, digest) {
  if (typeof sha !== 'string' || typeof digest !== 'string'
      || !SHA.test(sha) || !DIGEST.test(digest)) {
    throw new Error('Exactly one immutable source SHA and image digest required');
  }
}

export function attestArgs(sha, digest) {
  validateInput(sha, digest);
  return ['attestation', 'verify', 'oci://' + IMAGE + '@' + digest,
    '--repo', SOURCE, '--signer-workflow', SIGNER,
    '--source-digest', sha, '--source-ref', 'refs/heads/main',
    '--predicate-type', PROVENANCE, '--format', 'json'];
}

export function verifyAttestation(result, digest) {
  if (!Array.isArray(result) || !result.some(entry => {
    const statement = entry?.verificationResult?.statement;
    return statement?.predicateType === PROVENANCE
      && Array.isArray(statement?.subject)
      && statement.subject.some(s => s?.digest?.sha256 === digest.slice(7));
  })) throw new Error('CKA signer or published subject could not be verified');
}

export function verifyManifest(result) {
  if (!result || result.schemaVersion !== 2 || !Array.isArray(result.manifests)) {
    throw new Error('Expected immutable multiarch OCI manifest');
  }
  const platforms = result.manifests.filter(m => m?.platform?.os === 'linux');
  if (platforms.length !== 2 || platforms.some(m =>
    !DIGEST.test(m.digest) || !['arm64', 'amd64'].includes(m.platform.architecture))) {
    throw new Error('CKA image platforms are not precisely admitted');
  }
  for (const arch of ['arm64', 'amd64']) {
    if (platforms.filter(m => m.platform.architecture === arch).length !== 1) {
      throw new Error('Missing or duplicate required CKA image platform');
    }
  }
}

export function verifySourceRuns(commit, result, sha) {
  if (commit?.sha !== sha || !Array.isArray(result?.workflow_runs)) {
    throw new Error('Source main changed or source runs unavailable');
  }
  const matching = result.workflow_runs.filter(run =>
    run?.head_sha === sha && run.head_branch === 'main' && run.event === 'push'
    && run.status === 'completed' && run.conclusion === 'success'
    && run.repository?.full_name === SOURCE);
  for (const name of REQUIRED) {
    if (!matching.some(run => run.name === name)) {
      throw new Error('Required protected-main CKA source CI is not green: ' + name);
    }
  }
}

export function admit(sha, digest, runner = spawnSync) {
  validateInput(sha, digest);
  // All evidence is fetched anew. Do not trust a browser-selected manifest,
  // unverified attestation metadata, branch-only build or PR CI.
  const commit = invoke('gh', ['api', 'repos/' + SOURCE + '/commits/main'], runner);
  const runs = invoke('gh', ['api',
    'repos/' + SOURCE + '/actions/runs?head_sha=' + sha + '&per_page=100'], runner);
  verifySourceRuns(commit, runs, sha);
  const manifest = invoke('docker', ['buildx', 'imagetools', 'inspect', '--raw',
    IMAGE + '@' + digest], runner);
  verifyManifest(manifest);
  const signed = invoke('gh', attestArgs(sha, digest), runner);
  verifyAttestation(signed, digest);
  return Object.freeze({source_sha: sha, image_digest: digest,
    source_checks: REQUIRED.length, signed_provenance: true,
    arm64: true, amd64: true, deployment_performed: false});
}


const MULTIARCH = new Set([
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json'
]);

export function inspectPublishedDigest(output, sha) {
  if (typeof output !== 'string' || output.length > 2 * 1024 * 1024 || !SHA.test(sha))
    throw new Error('Published image metadata unavailable');
  const header = new Map();
  for (const line of output.split(/\r?\n/)) {
    const match = /^(Name|MediaType|Digest):[ \t]*(.*?)[ \t]*$/.exec(line);
    if (!match) continue;
    if (header.has(match[1])) throw new Error('Ambiguous published image header');
    header.set(match[1], match[2]);
  }
  if (header.size !== 3 || header.get('Name') !== IMAGE + ':sha-' + sha
      || !MULTIARCH.has(header.get('MediaType'))
      || !DIGEST.test(header.get('Digest'))) {
    throw new Error('Current CKA multiarch publication unavailable');
  }
  return header.get('Digest');
}

export function admitCurrent(runner = spawnSync) {
  // The per-commit tag is a locator only. Immediately freeze it to its
  // immutable digest, then run the full independent protected-main,
  // multiarch and signed-provenance checks against that digest.
  const source = invoke('gh', ['api', 'repos/' + SOURCE + '/commits/main'], runner);
  if (!SHA.test(source?.sha)) throw new Error('Current protected CKA source unavailable');
  const result = runner('docker', ['buildx', 'imagetools', 'inspect',
    IMAGE + ':sha-' + source.sha], {
    encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 * 1024
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== 'string')
    throw new Error('Current published CKA image unavailable');
  const digest = inspectPublishedDigest(result.stdout, source.sha);
  return admit(source.sha, digest, runner);
}

if (process.argv[1]?.endsWith('/cka_lab_image_admission.mjs')) {
  try {
    if (process.argv.length !== 4) throw new Error('Explicit SHA and digest required');
    const result = admit(process.argv[2], process.argv[3]);
    console.log('CKA_LAB_IMAGE_ADMITTED ' + JSON.stringify(result));
  } catch (error) {
    console.error('CKA_LAB_IMAGE_ADMISSION_BLOCKED');
    process.exitCode = 1;
  }
}
