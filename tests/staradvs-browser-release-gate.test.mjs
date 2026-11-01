import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pagesReleasePublished, PAGES_RELEASE_JOB } from '../scripts/staradvs_browser_release_gate.mjs';

const release = (conclusion, status = 'completed') => ({
  name: PAGES_RELEASE_JOB, conclusion, status,
});
const response = (...jobs) => ({ total_count: jobs.length, jobs });

test('only an actually published Pages run launches post-release browser QA', () => {
  assert.equal(pagesReleasePublished(response(
    { name: 'Verify source admission and Pages isolation', status: 'completed', conclusion: 'success' },
    { name: 'Admit current source main and check public HTTPS', status: 'completed', conclusion: 'success' },
    release('success'),
  )), true);
});

test('successful workflow with skipped release does not launch browser QA', () => {
  assert.equal(pagesReleasePublished(response(
    { name: 'Verify source admission and Pages isolation', status: 'completed', conclusion: 'success' },
    { name: 'Admit current source main and check public HTTPS', status: 'completed', conclusion: 'success' },
    release('skipped'),
  )), false);
});

test('failure, cancellation, pending, missing and ambiguous publish jobs fail closed', () => {
  for (const candidate of [release('failure'), release('cancelled'), release(null, 'in_progress')]) {
    assert.equal(pagesReleasePublished(response(candidate)), false);
  }
  assert.equal(pagesReleasePublished(response({ name: 'contracts', conclusion: 'success' })), false);
  assert.equal(pagesReleasePublished(response(release('success'), release('success'))), false);
});

test('truncated, malformed or paginated GitHub responses fail closed', () => {
  for (const payload of [null, {}, { total_count: 2, jobs: [release('success')] },
    { total_count: 101, jobs: Array(101).fill(release('success')) },
    { total_count: 1, jobs: null }, response(), { total_count: 1, jobs: [null] }]) {
    assert.equal(pagesReleasePublished(payload), false);
  }
});

test('workflow requires the publication gate only for upstream workflow_run', () => {
  const yaml = readFileSync(new URL('../.github/workflows/staradvs-public-browser.yml', import.meta.url), 'utf8');
  assert.match(yaml, /workflow_run:\s*\n\s+workflows:\s*\['Star Adventures staging Pages'\]/);
  assert.match(yaml, /needs\.contracts\.outputs\.upstream_published == 'true'/);
  assert.match(yaml, /github\.event_name == 'push'/);
  assert.match(yaml, /github\.event_name == 'workflow_dispatch'/);
  assert.match(yaml, /github\.event_name == 'schedule'/);
  assert.match(yaml, /scripts\/staradvs_browser_release_gate\.mjs/);
});
