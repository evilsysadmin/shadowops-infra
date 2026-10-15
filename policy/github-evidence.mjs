const OWNER = 'evilsysadmin';
const REPO = 'chronicles-of-matthias';
const WORKFLOW = 'staging-image.yml';
const WORKFLOW_ID = 386009048; // immutable ID from GitHub Actions' published staging image run
const SHA = /^[a-f0-9]{40}$/;

export async function verifyGithubBuild({sha, runId, token, fetchImpl = fetch}) {
  if (!SHA.test(sha || '') || !Number.isSafeInteger(runId) || runId <= 0) throw new Error('invalid release identifiers');
  if (!token) throw new Error('missing GitHub token');
  const base = 'https://api.github.com/repos/' + OWNER + '/' + REPO;
  async function get(path) {
    const response = await fetchImpl(base + path, {
      headers: {Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'},
      redirect: 'error'
    });
    if (!response.ok) throw new Error('GitHub verification failed: ' + response.status);
    return response.json();
  }
  const run = await get('/actions/runs/' + runId);
  if (run.head_sha !== sha || run.event !== 'push' || run.head_branch !== 'main' || run.status !== 'completed' || run.conclusion !== 'success') throw new Error('untrusted workflow run');
  if (run.path !== '.github/workflows/' + WORKFLOW || run.workflow_id !== WORKFLOW_ID || run.repository?.full_name !== OWNER + '/' + REPO) throw new Error('untrusted workflow identity');
  const commit = await get('/commits/' + sha);
  if (commit.sha !== sha) throw new Error('commit mismatch');
  const branch = await get('/branches/main');
  if (branch.protected !== true) throw new Error('main branch not protected');
  const lineage = await get('/compare/' + sha + '...main');
  if (!['ahead','identical'].includes(lineage.status) || lineage.behind_by !== 0) throw new Error('commit no longer belongs to main history');
  return Object.freeze({repository: OWNER + '/' + REPO, sha, workflow: '.github/workflows/' + WORKFLOW, conclusion: 'success', event: 'push', ref: 'refs/heads/main', runId});
}
