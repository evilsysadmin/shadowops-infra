# Star Adventures staging ShadowOps ID — read-only cutover inventory

The old public static publisher is paused by the protected-release source
policy. This inspection provides **current evidence**, but neither enables
the audience nor uploads a Cloudflare Pages Worker.

Run the offline contracts:

    python3 -m unittest discover -s tests -p test_staradvs_identity_readiness.py -v

From the protected Infra staging environment, the optional GET-only check is:

    python3 scripts/staradvs_identity_readiness.py inspect

It observes only the exact already-owned Pages project, custom domain and
Cloudflare DNS record, the production/preview fail-closed configuration flags,
whether the *name and type* of the Star Adventures app-only secret binding
are present, and the actual Pages aliases disclosed by Cloudflare. The
credential **value is never logged, exported or read**. Unexpected project
identity, source/branch or alias hostname blocks inspection.

A public HTTPS GET to the isolated staging Identity login with
app=staradvs checks that the target is explicitly recognized; a 200
from some other page is insufficient. Guest GET/HEAD probes then require 401
from the canonical root, index, bridge and release resources and 404 from
the main Pages alias and discovered current/immutable aliases. Redirects are
not followed, TLS verification is required, and no cookies or tokens are
provided.

The workflow runs offline tests on PRs and performs a sanitized live probe
only on trusted main after relevant source/workflow pushes, via manual dispatch,
or on its daily schedule. It reports
**PENDING** while any requirement is absent. A successfully completed
inventory job does not imply a playable or protected release.

Even if the inventory reaches next_gate_ready=true, its can_activate
remains false: a real signed-in session journey and revocation test, session
renewal, identity failure behavior, full historical alias review and a
rollback/forward plan still have to pass. There is no mutating deployment
step here.

**Historic static Pages deployments may remain accessible.** The read-only
probe covers current project aliases found via project metadata, not all
historic deployment IDs. Older aliases require a separately scoped
Cloudflare deployment inventory and an enforceable quarantine before
claiming universal protection.

## Historical Pages aliases (read-only)

The owned Pages project is queried using the operationally validated bare
`GET /deployments` for page 1, followed by `GET /deployments?page=N`
for later pages. Earlier requests combining `page` with `per_page`
returned HTTP 400 across other projects. All returned origins must match
the Star Adventures project and the expected Pages hostname; no opaque
deployment URL is written into public logs.

The audit follows up to eight pages and 192 distinct aliases, requiring
consistent provider page numbers and total counts, and rejecting repeated
pages, foreign domains and malformed metadata. The sanitized response
reports the provider's total, accepted page/deployment/alias counts and
any incomplete-enumeration reason. Inaccessible later pages retain the
earlier validated exposure observations; unexpected foreign records fail
closed.

Every accepted alias is probed anonymously at `/` and `/release.json`
with HTTPS verification, without cookies, tokens or redirect following.
Even if all provider-reported rows are observed and each sampled alias
responds 404, `historical_inventory_complete=false` remains a deliberate
security invariant: this alone cannot certify every past alias or
provider-level Access coverage. An empty list also proves nothing.
The audit is read-only, and no outcome here can authorize a deployment
without real signed-in and guest-denial E2E evidence.

If Cloudflare denies the history endpoint, readiness reports
`pages_historical_guest: inventory-unavailable` and
`next_gate_ready: false`. All secrets, upstream error bodies and
historic alias names remain out of the report.

## Cloudflare-reported total (observability only)

The Pages client preserves optional `result_info` on the bare
first-page GET and later page-indexed requests. If Cloudflare reports consistent `page`, `per_page`, `count`
and `total_count`, the sanitized report includes
`historical_deployments_reported_total` (otherwise `null`). This count
can reveal that 25 sampled deployments were only the first of many, but it
is never interpreted as proof of complete alias enumeration: several releases
may share one hostname, old aliases may exist outside the sample and a
single reported page is not an authenticated security check.

`historical_inventory_complete` stays false, including when reported
`total_count` equals the observed count. Invalid pagination metadata fails
closed; no secret, deployment URL or response body is logged.

## Multi-page historical exposure inventory

After confirming real `page=2` on the owned staging Pages project, the
read-only audit now requests subsequent pages using only `?page=N` (no
`per_page` override). It stops at the provider-reported total or at eight
pages / 192 unique aliases, whichever comes first. Each response must use
the expected project, approved hostname, page index and original total; an
empty, repeated, inconsistent, oversized or unavailable response is marked
as an incomplete audit. Hostnames are never printed. Existing first-page
results are retained when a later page is unavailable; malformed foreign
URLs block the audit instead of silently disappearing.

Guest HTTPS GET is performed for `/` and `/release.json` on **all accepted
sampled aliases**, not only the first page. The safe summary includes
`historical_pages_scanned`, `historical_enumeration_status`, cumulative
`historical_deployments_scanned` and `historical_aliases_scanned`. Even
`reported-total-observed` only means that the present API inventory rows
were sampled; `historical_inventory_complete` remains `false` because
Cloudflare metadata and temporary alias coverage cannot certify universal
historical isolation. Anonymous content or unproven Identity still blocks
all release/cutover paths, regardless of CI status.

## Aggregated guest-exposure counts

The sanitized live report also includes `historical_aliases_exposed`,
`historical_aliases_denied` and `historical_aliases_unverified`.
Each sampled hostname contributes exactly one count: a 200/206 from either
`/` or `/release.json` is exposed; only two 404s count as denied;
other responses (including redirects, 401/403, partial failures or TLS
errors) remain unverified. The three counts must sum to
`historical_aliases_scanned`. No hostname, redirect destination, response
body or user information is printed. These counts are exposure evidence,
**not** user/session authorization or complete historical coverage.

## Independent Cloudflare Access posture (GET only)

The trusted-main and scheduled readiness check now also reads the **Star
Adventures staging** Cloudflare Access policy scopes using an independent
protected environment secret `CLOUDFLARE_ACCESS_READ_TOKEN` with
`Access: Apps and Policies Read` permissions. It does **not** reuse the Pages
credential, obtain a write token, modify Access, or require the other games
to be configured. It lists all account applications only to detect overlapping
or malformed declarations, then reads policies only for the three exact
Star Adventures scopes: base `staradvs-staging.pages.dev`, previews
`*.staradvs-staging.pages.dev`, and custom
`staging.staradvs.shadowops.dpdns.org`.

The sanitized `cloudflare_access` and `cloudflare_access_scopes` fields
report missing, ambiguous, restricted-policy-candidate or unavailable policy
metadata. A missing/denied Access-read token is `read-token-unconfigured`
or `inventory-unavailable`; it is never treated as Access protection.

The `next_gate_ready` predicate additionally requires all three Access
scope policies to be restricted candidates. **This is not proof of live Access
enforcement, proper signed-in game sessions, or historical alias isolation.**
`can_activate=false` remains invariant, and the publisher stays paused
until an approved protected release passes live guest-denial and signed-in E2E.
