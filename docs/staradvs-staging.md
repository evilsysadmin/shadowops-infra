# Star Adventures staging · isolated Cloudflare Pages

**Current status:** contracts only. No DNS, Pages project, TLS certificate, origin or public URL is confirmed live by this document.

## Ownership and endpoint

- Source/build owner: `evilsysadmin/star-adventures` (React/TypeScript/Vite at `frontend/`; no mandatory backend).
- Infrastructure/release owner: **this repo** (`evilsysadmin/shadowops-infra`).
- Dedicated Cloudflare Pages project: `staradvs-staging`.
- Proposed HTTPS hostname: `staging.staradvs.shadowops.dpdns.org`.
- Immutable source SHA is required for every release; never build from a mutable branch after admission.
- Separate production hostname `staradvs.shadowops.dpdns.org` remains **out of scope** until staging has a verified live HTTPS build and rollback.

Cloudflare Pages avoids touching the **Chess Studio** tunnel, Render, OCI A1, Chronicle deployments, host ports, SSH credentials or MongoDB. The repository may use the existing infra-only `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets under the staging Actions environment, but these must be verified rather than assumed.

## Safe operations

- `python3 scripts/staradvs_pages.py self-test`: offline contract.
- `python3 scripts/staradvs_pages.py preflight`: GET-only, verify exact zone, hostname and dedicated project without exposing Cloudflare identifiers or token.
- `python3 scripts/staradvs_pages.py project`: create the dedicated Pages project only when absent. Reject any existing project that isn't exactly our name/main branch, and any foreign DNS.
- `python3 scripts/staradvs_pages.py domain`: assign this exact hostname only to this dedicated Pages project; create proxied CNAME to `staradvs-staging.pages.dev` **only if absent**; refuse an existing foreign or ambiguous record.
- `python3 scripts/staradvs_pages.py verify --sha <40 hex>`: real HTTPS/TLS root + non-fallback JS asset + immutable SHA from `/release.json`. HTTP status from DNS mutation is never enough. No insecure TLS bypass.
- DNS may need certificate validation/activation by Cloudflare Pages; do not advertise a live URL until HTTPS verification succeeds.

## Release-gating plan

A separately reviewed, trusted-`main` workflow will:
1. Require the exact source `main` SHA and completed **successful source-main CI** (core, React, browser).
2. Verify infra `main` is still current and run no Cloudflare mutator on PRs.
3. Build using a pinned source SHA and `npm ci`; attach exact source SHA as `release.json`.
4. Ensure isolated Pages project; publish `frontend/dist` using a pinned Wrangler version.
5. Recheck hostname ownership, associate custom domain, verify HTTPS root/JS/manifest, and record an auditable receipt.
6. Keep the earlier staging build if admission fails. Serial release lock and no concurrent DNS writers.
7. Later promote the **same verified source SHA/artifact** to production via independent approval and PR; no production changes in staging onboarding.

A Pages deployment is public. Star Adventures is currently a public source repository; do not include extracted proprietary Trek assets, models, scripts or secret API keys in the build.

See issue [#174](https://github.com/evilsysadmin/shadowops-infra/issues/174).


## Trusted-main staging publisher

`.github/workflows/staradvs-pages-staging.yml` now owns the **staging-only** publication. It evaluates after the workflow's first merge to Infra `main`, can be dispatched manually, and retries hourly for source-only changes. PR events only run offline contract tests; never receive Cloudflare credentials.

- Admits the exact current Star Adventures `main` SHA through `scripts/staradvs_source_admission.py`; one completed **push-to-main** CI run must contain both successful core and React/Chrome jobs for the exact SHA.
- Checks whether the public domain already serves precisely that SHA to avoid unnecessary redeploys.
- Uses an exact-SHA checkout, `npm ci`, and a static Vite build. Adds infra-owned `release.json` and no-cache manifest headers.
- Uses Infra `staging` environment `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`; does not request user credentials in PRs or print secrets.
- Double-checks that game and Infra main haven't advanced before the Cloudflare mutation.
- `wrangler@4.127.1` publishes only project `staradvs-staging`; domain reconciliation refuses foreign DNS.
- Retries genuine HTTPS/TLS, HTML entrypoint, JS MIME and release manifest for a bounded period. Only a successful check prints `STARADVS_STAGING_PUBLIC_READY` and uploads `staradvs-staging-verified-<SHA>` receipt.

### Known hardening item

On 2026-10-22, the GitHub API reported `evilsysadmin/star-adventures/main` with `protected=false`. The immutable SHA and independent CI checks provide a minimum staging admission gate, **not** the guarantees of branch protection. Establish required checks and protection (or ruleset) before allowing production promotion.

### Operational state

The workflow existing in Git is not itself evidence of a successful deployment. Until a trusted-main run provides the exact `STARADVS_STAGING_PUBLIC_READY` marker, do **not** call the custom hostname live. Failures caused by Cloudflare token scope, account routing, public DNS or certificate provisioning require remediation **without bypassing hostname ownership/TLS checks**.
