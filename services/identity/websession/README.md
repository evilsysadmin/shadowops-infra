# Staging browser session transport

`NewStagingHandler(issuer, seed)` connects the real transactional Mongo issuer
to HTTPS requests. The existing `cmd/staging` bootstrap does **not** construct
it. It needs a separately supplied staging signing seed and a staging issuer;
there is no in-memory session fallback.

Requests must arrive over TLS with Host `id-staging.shadowops.dpdns.org`.
Forwarded headers cannot assert HTTPS, host, client IP or an allowed Origin.
The only browser origins accepted are that central origin and the three staging
origins pinned in `handler.go` / `config/identity/platform-contract.json`.
These candidate origins still need operational verification before rollout.

| POST route | Origin | JSON body | Success |
| --- | --- | --- | --- |
| `/api/identity/login` | Central Identity only | `{"subject":"<central UUIDv4>","password":"..."}` | 204 + new central cookie |
| `/api/identity/token` | One of the three products | `{}` | 200 `{"token":"<audience-bound JWT>"}` |
| `/api/identity/refresh` | Central Identity or a product | `{}` | 204 + rotated central cookie |
| `/api/identity/logout` | Central Identity or a product | `{}` | 204 + cookie removal after revocation commits |

All mutations require an exact allowed Origin and `application/json`, with
bounded bodies and no unknown fields, trailing JSON, query credentials or
Authorization header. CORS preflight allows only POST and Content-Type for
that exact origin. The token audience is selected by the **server's origin
mapping**, never a request audience or subject. Failed authentication returns
401, storage failures 503, local abuse limits 429; none changes the cookie.
Responses are no-store and do not echo credentials, opaque handles or errors
from the database. A missing/duplicate session cookie is denied.

The new Identity host uses `__Host-shadowops_sso_staging`: Secure, HttpOnly,
SameSite=Lax, Path=/ and no Domain. This intentionally supersedes the earlier
design-only staging cookie name/path so sibling subdomains cannot plant a
Domain cookie with the same name. The existing Chess IdP is unchanged. This
is a browser-session cookie; Mongo enforces the original 24-hour absolute TTL.
Refresh does not extend it. Applications receive only their short-lived JWT,
never the central opaque session handle. Product APIs must still validate the
JWT and obtain trusted freshness evidence on every protected operation.

Abuse controls are bounded **per process**: 10 password attempts and 120 total
operations per socket peer per minute, globally 60 password attempts / 600
operations, and at most two concurrent password checks. Proxy IP trust and
distributed abuse controls are not implemented. Do not expose this through a
TLS-terminating proxy by trusting arbitrary forwarded headers.

The disposable Mongo replica CI runs `go test -race -count=1 -v ./websession`
**after** issuance tests (both use and clear the same synthetic collections).
Real HTTPS requests with a cookie jar prove one password login → three tokens
without additional accounts/sessions, signature/audience checks, rotation,
unchanged absolute expiry, stale-handle rejection, shared logout and another
browser's isolation. Negative cases cover origin/CSRF, duplicate cookies,
audience/subject injection, malformed bodies, invalid credentials and unavailable
Mongo. These are HTTP client tests, not browser visual/CORS execution tests.

This transport does not create or activate accounts: only synthetic active
central accounts exist in current fixtures. UUID login is an integration
contract, **not the final username/email login UX**. Central registration,
claimant verification/recovery, login UI, a trusted freshness service transport,
per-product adapters and explicit ownership-preserving legacy data links remain
to be implemented. No existing product trusts this handler, no endpoint is
published and `/readyz` stays 503. This is not a completed SSO rollout.
