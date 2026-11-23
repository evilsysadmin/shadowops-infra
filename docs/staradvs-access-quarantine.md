# Star Adventures staging — apply Cloudflare Access quarantine

The real 2026-11-23 guest inventory found **114 anonymously accessible
historical Pages aliases out of 114 provider-reported aliases**. The
existing publisher is paused. This manual operator workflow is a concrete
way to close the bypass without modifying Chronicles, Snooker, Football,
other games, DNS, Identity or production.

## One-time protected setup

Create a **dedicated Cloudflare API token** scoped to the correct account
with **Access: Apps and Policies Write** and the read capability needed
to inspect application/policy metadata. Store the token only as the
GitHub **staging environment secret** named:

    CLOUDFLARE_ACCESS_WRITE_TOKEN

Never paste the token into an Actions input, a PR, chat or a file. The
existing Pages API token is used **only for GET ownership validation**.
This is distinct from the optional periodic Access-read token.

## Execute

Open the manual GitHub Actions workflow:

https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-access-quarantine.yml

On the **main** branch, select **plan** first to inspect the exact
three scopes. Then select **apply**, enter the exact individual
Cloudflare Access operator sign-in email and confirmation:

    STARADVS_QUARANTINE_ACCESS

The apply job is protected by the existing GitHub staging environment,
the exact current main SHA and the same staging publisher concurrency
group. It creates *only missing* individually restricted Access apps,
in order:

1. Historical immutable previews: *.staradvs-staging.pages.dev
2. Base Pages URL: staradvs-staging.pages.dev
3. Custom domain: staging.staradvs.shadowops.dpdns.org

No Everyone, Bypass, email-domain, group, service token or cross-game
policy is created. Unexpected/overlapping Access apps abort all further
writes; existing safely restricted apps are not modified. If the
provider fails partway through, preserve previous protective changes
and rerun the same approved operation after reviewing the failure.
No automated rollback can reopen a public bypass.

## Verification: never trust the API receipt alone

The apply job uses a separate GET for each newly created app's
restricted policy and then probes the current provider-reported
historical aliases anonymously on / and /release.json. It fails if
any tested alias still returns anonymous 200/206 or the inventory is
empty. A successful result means **no anonymous 200 was observed**,
NOT that user authentication or all historical hosts are verified.

Cloudflare Pages officially documents a special Enable access policy
process for previews plus **separate base Pages and custom domains**.
An API-created wildcard must be verified on actual immutable Pages
aliases: if it does not enforce Access, complete that provider UI
procedure and rerun the guest scan. See:

https://developers.cloudflare.com/pages/platform/known-issues/
https://developers.cloudflare.com/pages/configuration/preview-deployments/

The Access reader intentionally treats challenges, redirects and
inconclusive HTTP results as **unverified**, not as proof of signed-in
application functionality. Review the generated sanitized audit.

## After quarantine

Do not unpause the Star Adventures publisher. Activate the unique
staradvs staging consumer in ShadowOps ID, run the existing protected
manual fail-closed Pages-policy and isolated Vault binding workflows,
then deploy the reviewed Identity edge Worker with proper rollback.
Only after real authenticated browser E2E, guest denial, revocation,
assets/deep links and historical bypass checks may
config/staradvs-protected-release.json change from pending-identity.

This workflow is manual-only. PR CI green does not mean Cloudflare
was changed; running plan does not mutate anything.


## Fail-closed guest evidence (postflight)

A Cloudflare Access login normally redirects guests. **A redirect is not
proof of protection.** The earlier quarantine postflight could succeed when
every URL returned an unverified redirect, timeout or generic denial merely
because it saw zero HTTP 200. This has been fixed.

The operator action now returns success only when the API enumeration is
complete against the reported deployment total and *every sampled historical
alias* has verified 404s on both guest endpoints, with current Pages aliases
denied-404 and canonical guest routes denied-401. Any 200/206, incomplete
pagination, inconsistent counts, 302, 403, timeout or unknown Access
challenge remains **PENDING** and requires explicit browser/Access evidence
review. A pending result does not automatically roll back restricted Access
policies or authorize a deployment. Successful postflight still does not
override `pending-identity` or replace signed-in E2E.

The Access write client itself now enforces exactly one approved hostname
and one narrowly scoped individual-email Allow policy, even if called
directly with an unexpected payload; extra settings or broad selectors
cannot reach the external POST endpoint.

## Cloudflare's normal 302 Access challenge

Cloudflare documentation says unauthenticated web clients typically receive a
302 to `https://<team>.cloudflareaccess.com/cdn-cgi/access/login/<host>`.
The previous all-404 criterion was useful for a deployed Worker but made
a **normally protected Pages deployment** perpetually pending.

The quarantine postflight now conducts an additional bounded, GET-only,
**no-redirect** inspection of every currently reported historical alias,
the current Pages aliases and the custom hostname. It recognizes a 302 only
if the exact request hostname appears in the Cloudflare team-domain Access
login path, on **both** `/` and `/release.json`. Non-HTTPS Locations,
wrong hosts, arbitrary redirects, foreign team hosts, timeouts, mixed
responses, changed provider history or anonymous 200/206 fail closed.
No redirect targets, opaque aliases or team identifiers are logged.

If all hosts are independently denied (404) or present exact Cloudflare
Access login challenges and all three **independently read-back** Access
policies are restricted, the workflow reports
`access-login-challenge-candidate`. This is a **quarantine candidate**,
not cryptographic proof of Cloudflare policy enforcement: an origin could
imitate a redirect. It never changes `can_activate=false`, bypasses
`pending-identity`, publishes Pages, or replaces an actual signed-in
gameplay and revocation E2E.

Sources:
- https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/
- https://developers.cloudflare.com/pages/configuration/debugging-pages/
