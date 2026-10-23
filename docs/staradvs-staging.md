# Star Adventures staging · isolated Cloudflare Pages

**Verified staging (2026-10-23):** Cloudflare Pages, exact public hostname ownership, HTTPS/TLS, HTML, JavaScript entrypoint, and immutable `/release.json` passed trusted-main release [run #39933614402](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39933614402), with receipt `staradvs-staging-verified-50103ddee9be669427759cd74c00d3e83293e6ea`. This proves that *release*, not that a future game `main` remains deployed; always compare the live manifest against the current source SHA.

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
- `python3 scripts/staradvs_pages.py manifest --sha <40 hex> --dist <built-dist>`: create a staging manifest with the SHA-256 of the actual Vite JavaScript entrypoint and no-store release headers, before uploading the built directory.
- `python3 scripts/staradvs_pages.py verify --sha <40 hex>`: real HTTPS/TLS root + non-fallback JS asset + immutable SHA and **exact served JS SHA-256** from `/release.json`. Reject mixed CDN assets even when the announced source SHA matches. HTTP status from DNS mutation is never enough. No insecure TLS bypass.
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

`.github/workflows/staradvs-pages-staging.yml` owns **staging-only** publication. It evaluates after relevant Infra `main` changes, accepts `workflow_dispatch`, and reconciles every 30 minutes for source-only changes (scheduled GitHub runs may be delayed; the 30-minute cadence bounds normal fallback lag without promising real-time dispatch). PR events only run offline contract tests; never receive Cloudflare credentials.

Star Adventures source CI may request that existing Infra `workflow_dispatch` **after both main core/browser jobs succeed**, using optional source-repo secret `SHADOWOPS_INFRA_ACTIONS_TOKEN`. The fine-grained token should be restricted to this Infra repository and **Actions: read/write**; do not put Cloudflare or host credentials in the game repository. The source job only requests publication: Infra rechecks exact source `main` SHA and completed green source-main CI, with a bounded finalization retry for dispatch requests; no trust is placed in dispatch parameters. If the token is absent or the request fails, source CI remains successful and half-hourly Infra reconciliation remains the fallback.

- Admits the exact current Star Adventures `main` SHA through `scripts/staradvs_source_admission.py`; one completed **push-to-main** CI run must contain both successful core and React/Chrome jobs for the exact SHA. GitHub sometimes returns a job as `in_progress` despite a successful conclusion and nonempty `completed_at` within a completed successful run; accept only that internally corroborated state, never pending or uncompleted jobs (observed on Star Adventures [run #39937715178](https://github.com/evilsysadmin/star-adventures/actions/runs/39937715178)).
- Checks whether the public domain already serves precisely that SHA to avoid unnecessary redeploys.
- Uses an exact-SHA checkout, `npm ci`, and a static Vite build. Generates infra-owned `release.json` with immutable source SHA and SHA-256 of its **actual JavaScript entrypoint**, plus no-cache manifest headers.
- Uses Infra `staging` environment `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`; does not request user credentials in PRs or print secrets.
- Checks that game and Infra `main` haven't advanced before mutation **and again after public verification**; if either changes while publishing, the run withholds the success receipt so the next reconciliation can publish current code.
- `wrangler@4.127.1` publishes only project `staradvs-staging`; domain reconciliation refuses foreign DNS.
- Retries genuine HTTPS/TLS, HTML entrypoint, JS MIME, release manifest and JS SHA-256 agreement for a bounded period. The `STARADVS_STAGING_PUBLIC_READY` marker is emitted **only after** final main-head checks and artifact upload `staradvs-staging-verified-<SHA>` succeed. The JS digest proves consistency of the deployed entrypoint with the built release, not reproducibility of third-party dependencies or a full-site security attestation.

### Known hardening item

On 2026-10-22, the GitHub API reported `evilsysadmin/star-adventures/main` with `protected=false`. The immutable SHA and independent CI checks provide a minimum staging admission gate, **not** the guarantees of branch protection. Establish required checks and protection (or ruleset) before allowing production promotion.

### Operational state

A workflow definition or successful admission job alone does not prove a live release. A trusted-main **publish job** must emit `STARADVS_STAGING_PUBLIC_READY` and upload a matching `staradvs-staging-verified-<SHA>` receipt. This was achieved in the verified run referenced above. Later release failures caused by token scope, Cloudflare, public DNS or certificate provisioning must be fixed **without bypassing hostname ownership/TLS checks**. A previous receipt never proves that the *latest* source `main` has deployed.
