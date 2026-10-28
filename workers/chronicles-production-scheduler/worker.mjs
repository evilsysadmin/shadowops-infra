// Opt-in external 08:00 Europe/Madrid trigger for the existing protected train.
// The Worker never deploys infrastructure, chooses a SHA, or bypasses admission.
const TARGET = 'https://api.github.com/repos/evilsysadmin/shadowops-infra/actions/workflows/chronicles-production-train.yml/dispatches';
const CRONS = new Set(['0 6 * * *', '0 7 * * *']);

export function madridClock(scheduledTime) {
  if (!Number.isSafeInteger(scheduledTime) || scheduledTime < 0) {
    throw new Error('invalid scheduled time');
  }
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(new Date(scheduledTime));
  const value = Object.fromEntries(parts.map(({ type, value }) => [type, value]));
  return { day: `${value.year}-${value.month}-${value.day}`,
    hour: value.hour, minute: value.minute };
}

export function isMadridEight(controller) {
  if (!CRONS.has(controller?.cron)) return false;
  const { hour, minute } = madridClock(controller.scheduledTime);
  return hour === '08' && minute === '00';
}

export async function dispatchMadridTrain(controller, env, send = fetch, now = Date.now) {
  // Cloudflare crons are UTC: at most one of 06:00/07:00 is 08:00 Madrid.
  // Check the nominal *scheduled* instant, not actual delayed invocation time.
  if (!isMadridEight(controller)) return { status: 'outside-madrid-slot' };
  if (env?.SCHEDULER_ENABLED !== 'true') return { status: 'disabled' };
  // Never turn a provider outage into an unexpected afternoon production release.
  // Use actual invocation time as well as the nominal Cron scheduled timestamp.
  const lagMs = now() - controller.scheduledTime;
  if (!Number.isFinite(lagMs) || lagMs < -60000 || lagMs > 300000) {
    return { status: 'missed-08-slot' };
  }
  const token = env?.GH_ACTIONS_TOKEN;
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('scheduler secret not configured');
  }
  const response = await send(TARGET, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ShadowOpsChroniclesScheduler/1',
    },
    body: JSON.stringify({
      ref: 'main', return_run_details: true,
      inputs: { automated: true, dry_run: false },
    }),
  });
  if (response.status !== 200) {
    throw new Error(`workflow dispatch not acknowledged (HTTP ${response.status})`);
  }
  // Never log an untrusted provider response or anything credential-bearing.
  const data = await response.json();
  if (!Number.isSafeInteger(data?.workflow_run_id) || data.workflow_run_id <= 0) {
    throw new Error('missing attributable GitHub run ID');
  }
  const day = madridClock(controller.scheduledTime).day;
  console.log(`CHRONICLES_EXTERNAL_TRAIN_DISPATCHED madrid_day=${day} run=${data.workflow_run_id}`);
  return { status: 'dispatched', day, runId: data.workflow_run_id };
}

export default {
  async scheduled(controller, env) {
    const result = await dispatchMadridTrain(controller, env);
    if (result.status !== 'dispatched') {
      console.log(`CHRONICLES_EXTERNAL_TRAIN_${result.status}`);
    }
  },
};
