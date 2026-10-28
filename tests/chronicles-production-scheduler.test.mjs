import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { madridClock, isMadridEight, dispatchMadridTrain } from '../workers/chronicles-production-scheduler/worker.mjs';

const controller = (iso, cron) => ({ scheduledTime: Date.parse(iso), cron });
const summer = controller('2026-07-15T06:00:00Z', '0 6 * * *');
const winter = controller('2026-11-15T07:00:00Z', '0 7 * * *');

test('UTC crons select precisely one Madrid 08:00 on either side of DST', () => {
  for (const [valid, wrong] of [
    [summer, controller('2026-07-15T07:00:00Z', '0 7 * * *')],
    [winter, controller('2026-11-15T06:00:00Z', '0 6 * * *')],
    [controller('2026-03-28T07:00:00Z', '0 7 * * *'), controller('2026-03-28T06:00:00Z', '0 6 * * *')],
    [controller('2026-03-29T06:00:00Z', '0 6 * * *'), controller('2026-03-29T07:00:00Z', '0 7 * * *')],
    [controller('2026-10-24T06:00:00Z', '0 6 * * *'), controller('2026-10-24T07:00:00Z', '0 7 * * *')],
    [controller('2026-10-25T07:00:00Z', '0 7 * * *'), controller('2026-10-25T06:00:00Z', '0 6 * * *')],
  ]) {
    assert.equal(isMadridEight(valid), true);
    assert.equal(isMadridEight(wrong), false);
  }
  assert.equal(isMadridEight(controller('2026-11-15T07:00:00Z', '0 * * * *')), false);
  assert.throws(() => madridClock(Number.NaN), /invalid scheduled time/);
});

test('inactive and off-slot invocations cannot dispatch, even with credentials', async () => {
  const forbidden = () => { throw new Error('network must not be used'); };
  assert.deepEqual(await dispatchMadridTrain(summer, { SCHEDULER_ENABLED: 'false', GH_ACTIONS_TOKEN: 'x' }, forbidden), { status: 'disabled' });
  assert.deepEqual(await dispatchMadridTrain(controller('2026-07-15T07:00:00Z', '0 7 * * *'), { SCHEDULER_ENABLED: 'true', GH_ACTIONS_TOKEN: 'x' }, forbidden), { status: 'outside-madrid-slot' });
  await assert.rejects(dispatchMadridTrain(summer, { SCHEDULER_ENABLED: 'true' }, forbidden, () => summer.scheduledTime + 1000), /secret/);
});

test('enabled Madrid slot dispatches only protected main, as automated, with attributable ID', async () => {
  let n = 0;
  const fakeFetch = async (url, options) => {
    n++;
    assert.equal(url, 'https://api.github.com/repos/evilsysadmin/shadowops-infra/actions/workflows/chronicles-production-train.yml/dispatches');
    assert.equal(options.method, 'POST');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, 'Bearer secret-test');
    assert.deepEqual(JSON.parse(options.body), {
      ref: 'main', return_run_details: true,
      inputs: { automated: true, dry_run: false },
    });
    return { status: 200, json: async () => ({ workflow_run_id: 12345 }) };
  };
  const original = console.log;
  const logs = [];
  console.log = (message) => logs.push(message);
  try {
    const result = await dispatchMadridTrain(winter, { SCHEDULER_ENABLED: 'true', GH_ACTIONS_TOKEN: 'secret-test' }, fakeFetch, () => winter.scheduledTime + 1000);
    assert.deepEqual(result, { status: 'dispatched', day: '2026-11-15', runId: 12345 });
    assert.equal(n, 1);
    assert.ok(logs[0].includes('run=12345'));
    assert.ok(!logs.join('').includes('secret-test'));
  } finally { console.log = original; }
});

test('provider failures fail closed, never accept non-attributable HTTP 204', async () => {
  const env = { SCHEDULER_ENABLED: 'true', GH_ACTIONS_TOKEN: 'redacted' };
  await assert.rejects(dispatchMadridTrain(summer, env, async () => ({ status: 204 }), () => summer.scheduledTime + 1000), /HTTP 204/);
  await assert.rejects(dispatchMadridTrain(summer, env, async () => ({ status: 200, json: async () => ({}) }), () => summer.scheduledTime + 1000), /attributable/);
});

test('delayed or clock-invalid cron event never dispatches production', async () => {
  const env = { SCHEDULER_ENABLED: 'true', GH_ACTIONS_TOKEN: 'redacted' };
  const forbidden = () => { throw new Error('delayed cron attempted a deployment'); };
  for (const time of [summer.scheduledTime + 300001,
                      summer.scheduledTime - 60001, Number.NaN]) {
    assert.deepEqual(
      await dispatchMadridTrain(summer, env, forbidden, () => time),
      { status: 'missed-08-slot' },
    );
  }
});

test('Wrangler configuration declares both UTC slots, but is disabled by default', () => {
  const config = readFileSync(new URL('../workers/chronicles-production-scheduler/wrangler.toml', import.meta.url), 'utf8');
  assert.match(config, /crons = \["0 6 \* \* \*", "0 7 \* \* \*"\]/);
  assert.match(config, /SCHEDULER_ENABLED = "false"/);
  assert.match(config, /workers_dev = false/);
  assert.doesNotMatch(config, /GH_ACTIONS_TOKEN\s*=/);
});

test('Worker rollout is manual only, defaults to offline verification and has an explicit disabled-deploy gate', () => {
  const workflow = readFileSync(
    new URL('../.github/workflows/chronicles-scheduler-worker-rollout.yml', import.meta.url),
    'utf8',
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\n  schedule:/);
  assert.doesNotMatch(workflow, /\n  push:/);
  assert.match(workflow, /options: \[verify, deploy_disabled\]/);
  assert.match(workflow, /default: verify/);
  assert.match(workflow, /DEPLOY_DISABLED_CHRONICLES_SCHEDULER/);
  assert.match(workflow, /npx --yes wrangler@4\.149\.0 deploy --dry-run/);
  assert.match(workflow, /npx --yes wrangler@4\.149\.0 deploy\n/);
  assert.match(workflow, /python3 scripts\/chronicles_scheduler_occupancy\.py/);
  assert.match(workflow, /test_chronicles_scheduler_occupancy\.py/);
  assert.ok(
    workflow.indexOf('python3 scripts/chronicles_scheduler_occupancy.py') <
    workflow.indexOf('run: npx --yes wrangler@4.149.0 deploy\n'),
    'occupancy preflight must precede any Cloudflare deployment',
  );
  assert.match(workflow, /github\.event_name == 'workflow_dispatch'/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /inputs\.operation == 'deploy_disabled'/);
  assert.match(workflow, /inputs\.confirmation == 'DEPLOY_DISABLED_CHRONICLES_SCHEDULER'/);
  assert.match(workflow, /environment:\n      name: production/);
  assert.match(workflow, /CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_API_TOKEN \}\}/);
  assert.match(workflow, /CLOUDFLARE_ACCOUNT_ID: \$\{\{ secrets\.CLOUDFLARE_ACCOUNT_ID \}\}/);
  assert.match(workflow, /SCHEDULER_ENABLED.*false/);
  assert.match(workflow, /workers_dev/);
  assert.doesNotMatch(workflow, /GH_ACTIONS_TOKEN:/);
  assert.doesNotMatch(workflow, /wrangler secret put/);
  assert.doesNotMatch(workflow, /schedule_trigger/);
});
