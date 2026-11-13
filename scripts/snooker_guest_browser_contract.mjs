// Real guest-browser contracts. URLs are pinned to the deployed staging
// product and its central Identity authority. No authentication is injected.
export const SNOOKER_ORIGIN = 'https://staging.snooker.shadowops.dpdns.org';
export const IDENTITY_ORIGIN = 'https://id-staging.shadowops.dpdns.org';
export const LOGIN_URL = IDENTITY_ORIGIN + '/login?app=snooker';
export const RETURN_URL = SNOOKER_ORIGIN + '/?shadowops=central';
export const GUEST_DENIED_PATHS = Object.freeze([
  '/', '/index.html', '/release.json', '/api/snooker/session', '/assets/guest.js',
]);

export function assertGuestStatus(path, status) {
  if (!GUEST_DENIED_PATHS.includes(path) || status !== 401) {
    throw new Error('SNOOKER_GUEST_BROWSER_DENIAL_FAILED');
  }
}
export function assertLoginReturnUrl(value) {
  if (value !== RETURN_URL) throw new Error('SNOOKER_GUEST_BROWSER_RETURN_URL_FAILED');
}
export function assertNoPrivilegedCookies(cookies) {
  if (!Array.isArray(cookies) || cookies.some(cookie =>
    cookie.name === '__Host-snooker_staging' ||
    cookie.name === '__Host-shadowops_sso_staging')) {
    throw new Error('SNOOKER_GUEST_BROWSER_COOKIE_LEAK');
  }
}
