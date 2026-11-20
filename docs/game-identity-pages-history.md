# ShadowOps ID · historical Cloudflare Pages alias audit

The existing generic audit checks canonical domain roots and predictable
Pages main aliases, but **not** the opaque older deployments. Old deployments
can remain anonymous even after a new Pages Worker secures the current
deployment. This is a real potential bypass, not just a missing UI redirect.

`scripts/game_identity_pages_history.py` queries the **seven** known Pages
projects for the eight registered ShadowOps game repositories (Tactics is not
independently published; Chess Studio is not Pages-hosted). It never guesses
an alias: every immutable/preview hostname comes from Cloudflare's exact
allowlisted project metadata or deployment inventory.

- Requires an owned project name, expected `main` production branch, no
  foreign source, scoped domains, and an actual `*.pages.dev` hostname
  derived from that project.
- Performs only Cloudflare GETs (project and paginated deployments) and
  public HTTPS GETs to each discovered main, current or historic hostname
  at `/` and `/release.json`. There are no browser cookies, redirects,
  Identity tokens, TLS exceptions, provider writes, or deploys.
- Uses the bare Cloudflare `GET /deployments` endpoint for each
  allowlisted project, matching the existing rollback inventory. The previous
  explicit `page=1&per_page=100` returned HTTP 400 across six live Pages
  projects. This initial compatibility pass inspects only the returned
  deployment page and probes at most 28 hostnames per project.
  **Historic coverage always stays NOT_FULLY_VERIFIED** until a separately
  verified pagination scheme with Cloudflare's real result_info is added.
  Missing/foreign records, limits and network errors likewise never count
  as protected.
- Any tested historical hostname returning HTTP 200 or 206 is flagged as
  REVIEW_ANONYMOUS_200, including a possible login shell. The response
  body and project secrets are never included in the log. A 401/403/404
  only establishes **guest denial**, not a working signed-in game.
- A Cloudflare Access 302/303/307 login redirect is recognized **only**
  when the Location is an HTTPS URL on a single `<team>.cloudflareaccess.com`
  hostname with the exact `/cdn-cgi/access/login/<requested-pages-host>`
  path. It is counted as `access_login_challenge_count`, separate from
  generic unknown redirects and anonymous-200 counts. **It is merely
  observational:** an origin can fabricate a 302, and it does not establish
  cryptographic enforcement, account eligibility, session revocation or
  full historic coverage. Unknown or foreign redirects remain unverified.
  The Location URL, team name, opaque Pages aliases and queries are
  never printed or persisted.
- Prints a small per-game summary with counts only. The Infra repository
  and Actions logs are public; **never** print historical/immutable deployment
  hostnames, even in sanitized partial examples. They would form an index of
  paths that currently bypass Identity. Operators can inspect exact hostnames
  in the owned Cloudflare Pages dashboard. This remains an exposure inventory,
  not a comprehensive account/session isolation certification.

The GH Actions workflow `Games · ShadowOps ID historical Pages alias exposure`
runs offline contracts for PRs and the read-only Cloudflare+HTTPS inventory
on relevant Infra main pushes, manual dispatch or every morning. The live
job uses the existing protected `staging` environment for Cloudflare
credentials, including read-only verification of the known Bridge Squad
production Pages project; **it never changes production assets**.

**Remediation:** do not mark any game as fully protected while an older
deployment serves anonymous content. Restrict all Pages preview/immutable
hosts with a provider-level protection policy or explicitly retire legacy
deployments under a separately reviewed operator workflow. Publishing a
Worker only to the newest deployment does not resolve old deployment URLs.

Passing this audit is a prerequisite for coverage claims, not a proof of
correct ShadowOps ID login, revocation, or per-account persistence.
