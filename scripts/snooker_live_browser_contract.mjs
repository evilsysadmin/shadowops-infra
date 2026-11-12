// A real staging browser journey must NEVER accept a mocked login/token,
// arbitrary URLs or a missing test account as a green run.
export const SNOOKER_ORIGIN = 'https://staging.snooker.shadowops.dpdns.org';
export const IDENTITY_ORIGIN = 'https://id-staging.shadowops.dpdns.org';
export const SHA = /^[a-f0-9]{40}$/;
const USERNAME = /^[A-Za-z][A-Za-z0-9_]{2,31}$/;

export function requireLiveBrowser(env) {
  if (env.SNOOKER_LIVE_BROWSER !== '1' ||
      !SHA.test(env.SNOOKER_SOURCE_SHA || '') ||
      !USERNAME.test(env.SNOOKER_E2E_USERNAME || '') ||
      typeof env.SNOOKER_E2E_PASSWORD !== 'string' ||
      [...env.SNOOKER_E2E_PASSWORD].length < 15) {
    throw new Error('SNOOKER_AUTH_BROWSER_BLOCKED: protected test account or exact release SHA missing');
  }
  return { sha: env.SNOOKER_SOURCE_SHA };
}

export function assertRelease(release, sha) {
  if (!SHA.test(sha) || !release || release.schema !== 1 ||
      release.application !== 'snooker-of-matthias' ||
      release.environment !== 'staging' || release.source_sha !== sha ||
      release.authentication?.provider !== 'shadowops-id' ||
      release.authentication?.audience !== 'snooker' ||
      release.authentication?.required !== true) {
    throw new Error('Exact authenticated Snooker release verification failed');
  }
}

export function assertAuthenticatedSession(session) {
  if (!session || session.identity !== 'snooker' ||
      typeof session.subject !== 'string' ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(session.subject) ||
      !Number.isSafeInteger(session.expires_at) ||
      session.expires_at < Math.floor(Date.now() / 1000) + 5) {
    throw new Error('Snooker real session missing or near expiry');
  }
}
