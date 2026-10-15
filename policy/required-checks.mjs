const REPO = 'evilsysadmin/chronicles-of-matthias';
const SHA = /^[a-f0-9]{40}$/;

// These five jobs are owned by the current Chronicles CI and image-publish
// workflows. They are policy, NEVER caller-provided release-dispatch data.
export const TRUSTED_CHECKS = Object.freeze([
  'repository-contract',
  'build-and-test',
  'smoke',
  'staging-image-policy',
  'publish-staging-image',
]);

const CHECK_URL = /^https:\/\/github\.com\/evilsysadmin\/chronicles-of-matthias\/actions\/runs\/([0-9]+)\/job\/[0-9]+$/;
const SOURCE_WORKFLOW_JOBS = new Set(['staging-image-policy','publish-staging-image']);

export async function verifyRequiredChecks({
  sha, token, sourceRunId, requiredContexts, fetchImpl = fetch
}) {
  if (!SHA.test(sha || '') || !token || !Number.isSafeInteger(sourceRunId) || sourceRunId <= 0) {
    throw new Error('invalid required-check evidence inputs');
  }
  // Do not allow a dispatch payload to define or downgrade its own gates.
  if (requiredContexts !== undefined) throw new Error('caller-provided required checks forbidden');
  const url = 'https://api.github.com/repos/' + REPO + '/commits/' + sha + '/check-runs?per_page=100';
  const response = await fetchImpl(url, {
    headers:{
      Authorization:'Bearer '+token,
      Accept:'application/vnd.github+json',
      'X-GitHub-Api-Version':'2022-11-28'
    },
    redirect:'error'
  });
  if (!response.ok) throw new Error('check runs query failed');
  const data = await response.json();
  if (!Number.isSafeInteger(data.total_count) || data.total_count > 100 ||
      !Array.isArray(data.check_runs) || data.check_runs.length !== data.total_count) {
    throw new Error('check runs are missing or pagination is incomplete');
  }
  for (const name of TRUSTED_CHECKS) {
    const matches = data.check_runs.filter(run => run.name === name && run.head_sha === sha);
    if (matches.length !== 1) throw new Error('missing or ambiguous trusted check: '+name);
    const run = matches[0];
    const match = CHECK_URL.exec(run.details_url || '');
    if (run.status !== 'completed' || run.conclusion !== 'success' ||
        run.app?.slug !== 'github-actions' || !match ||
        (SOURCE_WORKFLOW_JOBS.has(name) && Number(match[1]) !== sourceRunId)) {
      throw new Error('untrusted or failed required check: '+name);
    }
  }
  return Object.freeze({sha, requiredContexts: Object.freeze([...TRUSTED_CHECKS])});
}
