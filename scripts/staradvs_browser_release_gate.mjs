// Gate workflow_run browser QA on the actual Pages publication job, not just
// the parent workflow's green conclusion (which also covers skipped releases).
export const PAGES_RELEASE_JOB = 'Publish exact source to isolated Cloudflare Pages staging';

export function pagesReleasePublished(response) {
  // Fail closed on incomplete API responses, pagination, or ambiguous jobs.
  if (!Number.isSafeInteger(response?.total_count) ||
      response.total_count < 1 || response.total_count > 100 ||
      !Array.isArray(response.jobs) ||
      response.jobs.length !== response.total_count) return false;

  const releases = response.jobs.filter(job => job?.name === PAGES_RELEASE_JOB);
  return releases.length === 1 &&
    releases[0].status === 'completed' &&
    releases[0].conclusion === 'success';
}
