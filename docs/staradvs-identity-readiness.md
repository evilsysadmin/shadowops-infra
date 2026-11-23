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

The cutover inventory now pages through the Cloudflare Pages deployment API,
including historical immutable and branch aliases seen on the first returned
page, not merely the latest two project pointers. Each validated Pages hostname is probed anonymously at `/`
and `/release.json` using GET; only universal 404 qualifies as historical
alias denial. Results include sanitized counts and `pages_historical_guest`.
Malformed/foreign hosts, provider errors, incomplete pagination, and inventories
above the bounded 64-host probe limit fail closed (no cutover authorization).
The audit uses the documented **bare GET /deployments** endpoint only.
The explicit `page/per_page` query returned HTTP 400 across six owned Pages
projects in the shared audit. The client now retains optional
`result_info` for the first page, but cannot enumerate later pages. Only the
returned first page is sampled, **never**
the complete historical inventory. `historical_inventory_complete=false`
is invariant until a separately tested pagination contract is implemented.
Even unanimous 404 responses are reported as `sample-denied-404`, never
full guest-denial certification. An empty list is not verification. The live
cutover gate stays blocked regardless of this sample.

The audit uses a bounded eight-worker read-only probe pool; it never changes
DNS, Pages deployments, or Identity credentials. Cloudflare's canonical
project hostname is checked separately; this check does not establish a signed-in
user journey and cannot itself authorize a protected release.

If Cloudflare denies even the bare GET deployment-list API, readiness
reports `pages_historical_guest: inventory-unavailable` and `next_gate_ready:
false` rather than treating inaccessible history as empty or green. The audit
workflow remains diagnostically successful/pending, with no mutation. A
malformed or foreign deployment record continues to raise an error.

## Cloudflare-reported total (observability only)

The Pages client now preserves optional `result_info` on the existing bare
GET request. If Cloudflare reports consistent `page`, `per_page`, `count`
and `total_count`, the sanitized report includes
`historical_deployments_reported_total` (otherwise `null`). This count
can reveal that 25 sampled deployments were only the first of many, but it
is never interpreted as proof of complete alias enumeration: several releases
may share one hostname, old aliases may exist outside the sample and a
single reported page is not an authenticated security check.

`historical_inventory_complete` stays false, including when reported
`total_count` equals the observed count. Invalid pagination metadata fails
closed; no secret, deployment URL or response body is logged.

## Cloudflare page-2 read-only canary

Cloudflare documents the optional `page` query parameter, but previous
operational requests using `page=1&per_page=100` returned HTTP 400. When
its first response indicates more deployments than were sampled, the auditor
now issues **only** `GET /deployments?page=2` against the owned Pages
project, keeping the working first-page GET unchanged. It checks the second
page's record shapes, exact project hostnames, pagination metadata, total
consistency and whether the result merely repeats the first page. Results
are sanitized: `historical_page2_status`,
`historical_page2_deployments_indexed` and
`historical_page2_aliases_indexed`. No second-page hostname is printed
or publicly probed in this canary. An HTTP error becomes
`provider-unavailable` while retaining the first-page exposure report;
foreign/malformed data fails closed. The historical coverage flag remains
false and the release cannot be authorized by this probe. Only after a
successful live canary should a separately reviewed full-enumeration PR
attempt all pages and perform anonymous guest probes.

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
