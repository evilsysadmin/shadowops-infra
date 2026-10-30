# Staging central account and browser session

`NewStagingBrowserHandler(ctx, issuer, seed)` provides the central login page
and new-account enrollment over the real transactional Mongo issuer. The
existing `cmd/staging` bootstrap does **not** instantiate it. The handler needs
an independent staging signing seed and direct TLS for Host
`id-staging.shadowops.dpdns.org`. Forwarded headers cannot assert HTTPS, host,
client IP or an allowed Origin. There is no in-memory authentication fallback.

`GET /login?app=chronicles` serves the Spanish login/signup/recovery page.
`app` is one of chronicles, chess-studio, cka-simulator; the server pins its
return origin. Duplicate/unknown app or redirect parameters are denied.
The page uses same-origin JSON, CSP without inline/external scripts, labels,
keyboard focus, responsive forms and no browser credential storage. The return
URL carries only `?shadowops=central`, never a token, code or handle.

| POST route | Origin | JSON body | Success |
| --- | --- | --- | --- |
| `/api/identity/register` | Central Identity | username,password | 201 + one-time recoveryCode; no session |
| `/api/identity/login` | Central Identity | username,password | 204 + new central cookie |
| `/api/identity/recover` | Central Identity | username,password,recoveryCode | 200 + rotated code; all old sessions revoked |
| `/api/identity/token` | A pinned staging product | {} | 200 with audience-bound token |
| `/api/identity/refresh` | Central or a pinned product | {} | 204 + rotated cookie |
| `/api/identity/logout` | Central or a pinned product | {} | 204 + cookie removal after revocation commits |

Registration creates a new UUID, not a link to existing product data. See
[native account semantics](../issuance/NATIVE-ACCOUNTS.md). Recovery shows a
new backup code once and requires signing in again. Passwords/codes are cleared
from form inputs after requests; no email recovery is claimed.

All mutations require exact allowed Origin and application/json, bounded bodies,
no unknown fields/trailing JSON/query credentials/Authorization header. CORS
permits only POST+Content-Type for that exact origin. Token audience comes from
the server's origin mapping, never a request audience/subject. Errors do not
change cookies: 401 denied, 409 name unavailable, 503 storage unavailable, 429
local limit. Duplicate/missing cookies are denied. Responses are no-store and
never echo raw handles, passwords or database error details.

The host uses `__Host-shadowops_sso_staging`: Secure, HttpOnly, SameSite=Lax,
Path=/, no Domain. It is a browser-session cookie; Mongo enforces the original
24-hour absolute TTL, which refresh cannot extend. Apps receive only short
JWTs, never the central cookie/handle. Product APIs must verify JWTs and obtain
trusted freshness evidence for every protected operation.

Limits are per process: 10 credential operations / 120 total operations per
socket peer per minute, globally 60 credential / 600 total, at most two concurrent
KDFs. Proxy IP trust and distributed abuse controls remain deployment work.
The older `NewStagingHandler` remains a low-level UUID/password integration
adapter, with registration/page disabled; the browser constructor rejects UUID
login and only resolves native central names.

Replica CI runs issuance and HTTP tests sequentially, then actual Chromium with
real Mongo, TLS cookies and CORS. It covers signup/login/recovery, three-audience
signatures, rotation/logout, another browser, replay, injection, invalid
credentials and unavailable Mongo. Desktop/mobile captures are taken before
entering credentials or displaying backup codes. Product pages in the Chromium
fixture are **synthetic consumers**, not the actual games.

The opt-in [trusted freshness transport](FRESHNESS-TRANSPORT.md) adds an
authenticated backend RPC with fixed per-application credentials. No endpoint
is deployed and no existing product trusts this handler. Consumer wiring,
real product rollout and deployment/rollback remain required. The low-level
handlers and old bootstrap keep `/readyz=503`; the explicitly configured
[TLS runtime](../runtime/README.md) adds readiness after authenticated startup.
Chronicles has its own opt-in adapter, still disabled in deployment. The actual
staging login is not switched by adding this page.
