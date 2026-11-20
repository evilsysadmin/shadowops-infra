# Historical Pages bypasses — Cloudflare Access cutover for ShadowOps games

The read-only historical Pages audit [run #44817657296](https://github.com/evilsysadmin/shadowops-infra/actions/runs/44817657296)
observed anonymous HTTP 200 on **26/26** sampled Chronicles staging aliases,
**22/23** sampled Chronicles production aliases and **26/26** sampled
Star Adventures staging aliases. HTTP 200 could be a public login shell; for
Star Adventures the prior canonical audit confirmed actual static content.
**The currently deployed resources are not certified as protected.**

## Important: two distinct Cloudflare Access surfaces

Cloudflare's Pages documentation states that enabling preview protection
covers immutable `<hash>.<project>.pages.dev` URLs but **not**
`<project>.pages.dev` or your own custom domain. Their documented procedure
for full project protection includes a separate base `pages.dev` Access
application, a preview wildcard application, and a custom-domain companion
application where applicable. Do not treat one wildcard app as all three.

Official docs (not dashboard screenshots):
- https://developers.cloudflare.com/pages/configuration/preview-deployments/
- https://developers.cloudflare.com/pages/platform/known-issues/#enable-access-on-your-pagesdev-domain
- https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/

Cloudflare also warns that changing Access on the base Pages project without
configuring the custom domain can break the login experience for legitimate
visitors. Preserve each game's **own ShadowOps ID issuer and backend**
as the actual game-session authority. Access here is an additional
provider-level quarantine for direct Pages addresses, not a substitute for
ShadowOps ID, revocation checks or account data isolation.

## Read-only operator preflight

`scripts/pages_access_readiness.py inspect` inspects exactly:

| Owned Pages project | Direct Pages origin | Immutable previews | Companion custom hostname |
| --- | --- | --- | --- |
| chronicles-production | chronicles-production.pages.dev | *.chronicles-production.pages.dev | chronicles.shadowops.dpdns.org |
| chronicles-staging | chronicles-staging.pages.dev | *.chronicles-staging.pages.dev | staging.chronicles.shadowops.dpdns.org |
| staradvs-staging | staradvs-staging.pages.dev | *.staradvs-staging.pages.dev | staging.staradvs.shadowops.dpdns.org |

It uses an **independent** Cloudflare token with
`Access: Apps and Policies Read` permissions, stored as a **staging protected
environment** secret named `CLOUDFLARE_ACCESS_READ_TOKEN`. Do not reuse
the Pages Write token, and do not copy the token into code, logs, workflows
inputs or chat. The auditor calls only
`GET /accounts/{account_id}/access/apps` and the policies for the
**exactly matched** application UUIDs. It rejects incomplete application
pagination, unrecognized destinations, public-path overrides, duplicate
scopes and bypass/Everyone policies. It logs only app-scope classifications,
never application identifiers, rule text, emails, Access users or opaque
Pages deployment addresses.

Run `Pages · game Cloudflare Access bypass preflight (read-only)` from GitHub
Actions on **main** with `operation=inspect`. Pull requests and pushes
run only offline contracts. A missing token or insufficient API permission
blocks the live inspection; it never counts as a protected state.

A `CONFIGURED_FOR_GUEST_TEST` result is only Access configuration metadata,
not protection proof. `can_activate=false` is fixed by design.

## Controlled remediation sequence — start with Chronicles production

1. Capture current own-domain login, existing session and historical-alias
   probe baselines; ensure no unrelated Pages deploy/rollback is in flight.
2. In Cloudflare Workers & Pages, open the **exact** Pages project.
   Use Settings > General > Enable access policy for preview deployments.
3. Per Cloudflare's documented procedure, use Manage on the generated
   Access app and remove the wildcard to apply that app to the project
   `<project>.pages.dev` root. Return to Pages and re-enable preview
   protection to create the separate wildcard preview app.
4. Since each game uses a custom domain, configure the documented
   self-hosted companion Access application carefully, choosing a
   restrictive approved operator policy. Check that the canonical site's
   ShadowOps ID login, session refresh, API isolation and normal play still
   work. **Do not grant unauthenticated bypasses to make a broken login
   appear functional.**
5. Rerun the Access GET-only inspection and the **actual live** historical
   Pages guest audit. Reject anonymous application bytes, even if the
   visitor is redirected to a plausible-looking login page. For Access
   302/403, inspect a bounded Location/Access origin without following
   redirects, then verify signed-in behavior separately.
6. Validate logged-out access, logout/revocation, cross-account permissions,
   deep links, JS/assets, production and preview aliases, plus rollback
   compatibility before declaring the cutover. Use reviewed rollback
   procedures if the custom domain is disrupted; no deletion of historic
   deployments in this plan.

No existing workflow creates, edits, destroys or applies Access policies
as part of this iteration. Cloudflare Pages/Access credentials and approval
for a mutating operation remain separate. A green offline PR check must
never be described as the live cutover.

**Remaining scope:** after the three exposed projects, repeat the same
provider-level review for Football, Snooker and Bridge Squad; Pawn Action
Pages remains undeployed. Existing frontend and API ShadowOps ID authority
must be verified separately for every game.
