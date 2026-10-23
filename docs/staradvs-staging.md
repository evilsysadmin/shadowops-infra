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

Star Adventures source CI may request that existing Infra `workflow_dispatch` **after both main core/browser jobs succeed**, using optional source-repo secret `SHADOWOPS_INFRA_ACTIONS_TOKEN`. The fine-grained token should be restricted to this Infra repository and **Actions: read/write**; do not put Cloudflare or host credentials in the game repository. The source job only requests publication: Infra rechecks exact source `main` SHA and completed green source-main CI. If the game or Infra branch advances **after** checkout but before publication, the release deliberately fails with `STARADVS_STAGING_SUPERSEDED`, a GitHub warning and a Job Summary showing the pinned/current source SHAs. This is a fail-closed *supersession*, not a Cloudflare deployment failure: the old revision is never published; the next trusted run will reconcile the latest green source. It does **not** silently pass or auto-dispatch a replacement. Both manual/CI dispatches **and Infra `main` pushes** have a bounded 28-attempt (~4.5-minute) join window to handle an in-flight source Chrome CI; each retry requires both source and Infra `main` SHA to stay unchanged. Scheduled reconciliation stays fail-fast and no trust is placed in dispatch parameters. If the token is absent or the request fails, source CI remains successful and half-hourly Infra reconciliation remains the fallback.

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

## Real public-browser admission (not production approval)

The read-only `.github/workflows/staradvs-public-browser.yml` is owned by Infra. On a relevant Infra `main` change, a successful trusted-main `Star Adventures staging Pages` workflow, manual dispatch or the daily check, it:

1. Reads the **actual HTTPS staging** `/release.json` from the fixed hostname. Rejects redirects, wrong environment and missing `entry_js.sha256`.
2. Checks out Star Adventures at **that exact published SHA**, installs its pinned Playwright dependency with `npm ci --ignore-scripts` and uses the runner Chrome. No local game server or deployment credentials.
3. Exercises the real public `/bridge` deep link at **390px and 1280px**, including first-person navigation, science choice, two F5 reloads, persistent ending and horizontal overflow assertions.
4. Compares the public JS SHA-256 against its release manifest before testing, then confirms the public build/asset identity has not changed during the journey. Keeps short-lived screenshots.
5. Prints `STARADVS_PUBLIC_JOURNEY_READY sha=<SHA>` **only after** all actual browser assertions pass. PR events run offline contract tests, never real browsing or mutations.

**Scope:** This verifies the *published revision*, not necessarily the latest source `main`. Compare those SHAs when claiming freshness. No production, rollback, account security, full graphical fidelity or cross-device server-side persistence is implied. Browser captures are evidence to inspect, not automatic visual sign-off.

## Rollback inventory — discovery only

The dedicated Cloudflare Pages project is named `staradvs-staging`. Its Pages **production** deployment means the `main` branch of this *staging project*, **not** the ShadowOps game production environment or `staradvs.shadowops.dpdns.org`.

`.github/workflows/staradvs-rollback-inventory.yml` runs offline contracts in PRs and may run a **GET-only** inventory after trusted Infra `main` changes or manual dispatch. The workflow uses the existing Infra `staging` Cloudflare credentials but its program has **no mutation or rollback method**.

- Reverify public staging TLS, HTML, JS and SHA-256 release integrity and confirm exact project/DNS/custom-domain ownership before querying deployment metadata.
- Inspect only the first/default page of Cloudflare Pages deployments (with production deployments filtered locally) for project `staradvs-staging`. Keep only entries with successful deployment stage, clean `main` source commit SHA, correct project ID/name and valid deployment UUID. The public live SHA must match at least one such entry or the run fails closed.
- Query read-only GitHub Actions release history (up to 100 recent workflow runs / 40 successful trusted-main runs). For each Pages candidate, require a matching **unexpired, nonempty** `staradvs-staging-verified-<SHA>` artifact associated with a successful trusted-main `Star Adventures staging Pages` run. Missing, expired or mismatched receipts never certify a rollback candidate. The workflow has explicit GitHub Actions read permission; the game repository receives no new token.
- Print `STARADVS_STAGING_ROLLBACK_READONLY_PLAN` with the public SHA, potential earlier revisions, and a separate `receipt_backed_previous` list containing corroborating Infra workflow run and artifact IDs. If prior candidates exist but no matching receipt exists, the inventory job **fails closed**. Candidates are **not yet approved** as rollback targets: the first page may be incomplete, and archived GitHub verified release receipts and asset/browser checks must be independently reviewed.
- This step does not change an alias, publish bytes, create/delete a Pages deployment, modify DNS or perform a rollback. A later rollback workflow requires a separate reviewed and explicitly approved procedure, a source/release proof, post-rollback HTTPS/browser checks, and a clear path forward.

Cloudflare's documented Pages rollback operation is a **separate POST** endpoint; this inventory intentionally uses only the documented **GET** deployments list. Running this workflow proves inventory visibility, not rollback recoverability.

## Operator hold for a controlled staging restoration

`config/staradvs-staging-hold.json` is an explicitly reviewed, staging-only switch. Its checked-in default is `{ "mode": "auto" }`, so normal staging reconciliation remains unchanged. This is **not** itself a rollback workflow.

To prepare a future controlled rollback, first confirm no older staging publish run is still mutating Pages. Then submit a reviewed Infra PR changing the file to the exact JSON shape below, with an SHA from the actual publicly verified staging release, a short reason, an Infra issue, and a UTC deadline less than 24 hours away:

```json
{
  "mode": "hold",
  "anchor_sha": "<40-character-sha-of-currently-verified-staging-release>",
  "expires_at": "<future-UTC-YYYY-MM-DDTHH:MM:SSZ-within-24-hours>",
  "reason": "Controlled staging recovery rehearsal with manual checks",
  "issue": "#174"
}
```

Hold lifecycle:

- A valid active hold makes the normal candidate job **skip source admission and publication** (`STARADVS_STAGING_HOLD_SKIP`); scheduling, push and manual dispatch cannot bypass it. No DNS or Pages mutations are made by that skipped release.
- Hold state is rechecked in the trusted release job **before any Cloudflare mutation and immediately before Wrangler deploy**. A hold applied while an existing release is compiling blocks that release, provided it reaches the guarded check after the Infra `main` change. The existing exact Infra-main freshness checks also prevent previously checked-out workflows from ignoring a newer reviewed hold.
- A missing, corrupt, extra-field, malformed, future-too-distant or **expired** hold file blocks with a nonzero result rather than silently returning to auto. An expired hold requires an explicit reviewed change; it never resumes publication on its own.
- To finish a drill, first verify the restored release and intended forward source. Use a **new reviewed PR** to change the file back to `{ "mode": "auto" }`; the normal main-triggered reconciliation may then publish the latest green source again. Re-check public HTTPS/JS digest and Chrome journey afterward.
- The hold only governs this `staradvs-pages-staging.yml` workflow. Future mutating rollback must share its existing `shadowops-staradvs-staging-pages` Actions concurrency group, and must check the hold independently before any Cloudflare POST. It is not safe to presume this file blocks external Cloudflare/dashboard deploys or direct calls from other workflows.

**Important race:** Git PR merges are not atomic with an in-flight Cloudflare API call. Do not activate the hold until earlier trusted Pages publishers are drained and the new hold's main-run logs show it is active. This check provides an enforceable gate for the owned publisher, not a distributed lock around Cloudflare itself. No restoration or production DNS change is implied by creating the hold.

## Read-only restoration rehearsal (no rollback executor)

Once Pages has receipt-backed candidates, run `.github/workflows/staradvs-recovery-preflight.yml` in Infra to prepare a reproducible **rollback → HTTPS/browser validation → roll-forward** plan without changing Cloudflare or DNS. A `main` push touching the workflow/script/tests tests the live plan automatically; PRs only run offline tests. Manual dispatch may choose an optional **full, exact 40-character source SHA**, otherwise the most recent receipt-backed historical Pages release is selected.

The preflight reads the current public `/release.json` and checks actual HTML/JS SHA-256; confirms the dedicated Cloudflare zone, Pages project, hostname and domain ownership; enumerates successful clean `main` Pages deployments; corroborates previous SHA with unexpired trusted-main Infra release receipt; then GETs the **exact historical deployment UUID** for a second source/environment/success comparison. It also opens the deployment's immutable `https://<hash>.staradvs-staging.pages.dev` URL and verifies genuine TLS, no redirects, a matching `release.json`, the expected HTML entrypoint and the *actual JavaScript SHA-256*. It rejects mutable Pages branch aliases, foreign hosts, mismatched bytes and wrong MIME types. An immutable deployment URL is not a substitute for post-rollback public-browser testing. It rereads the public live SHA before declaring a consistent plan. Drift or missing evidence fails closed.

With checked-in `mode: auto`, result is `preview_only`, `hold: inactive`, `can_mutate: false` and `operator_approval: not_given`. Even with a committed active hold it reports `held_preflight_only`, keeping `can_mutate: false`; the hold must match the *pre-rollback* publicly verified anchor SHA. **No rollback is performed or permission granted by this preflight.**

The report identifies `forward_sha`, historic `target_sha`, exact Pages deployment UUID, trusted Infra publish run and artifact IDs and an informational **POST** rollback path, but never sends POST. A mutating rollback/roll-forward executor requires separate review, coordination with publisher concurrency/hold and public HTTPS/JS/Chrome/F5 checks after each transition. This preflight cannot guarantee state stays unchanged after it completes.

Cloudflare documents rollback as `POST /accounts/{account_id}/pages/projects/{project_name}/deployments/{deployment_id}/rollback`. The Pages production **branch** in this isolated staging project does not refer to the separate ShadowOps game production hostname.

## Guarded rollback transaction code (not activated)

After live GET-only checks passed, `scripts/staradvs_recovery_transaction.py` implements a **non-exposed transaction core** for a single Cloudflare Pages rollback. It has NO executable CLI entry point and no existing workflow imports or calls it. The independent `.github/workflows/staradvs-recovery-preflight.yml` continues to perform GET-only live verification and offline transaction tests. This commit does **not** perform any rollback.

Default `config/staradvs-recovery-authorization.json` is `{ "mode": "disabled" }`. To prepare a later *separately reviewed* mutating workflow, first drain existing staging publications, activate an issue-linked hold anchored to the actual public pre-rollback SHA, and review a separate, short-lived authorization record with exact operation `rollback`, `live_sha`, `target_sha`, Pages UUID, Infra publish run ID, unexpired receipt ID, issue and expiry within two hours. All must match the independent fresh preflight including immutable historic JS proof. A typed operator confirmation must be `ROLLBACK <exact-live-sha> TO <exact-target-sha>`.

Transaction core refuses the wrong GitHub repo/ref/event/environment, missing/malformed/expired auth or hold, mismatched SHA/UUID/receipt, stale public SHA, a changed hold or missing main-freshness callbacks **before** any Cloudflare mutation. A future manually authorized workflow would have to run on Infra `main` with a separate `staging-recovery` environment, verify exact current Infra main SHA and shared staging publisher concurrency, then call this code. No such mutating workflow is wired yet. The checked-in authorization must remain disabled until this second review.

When properly called by a future approved workflow, the core allows only a single `POST /accounts/{account_id}/pages/projects/staradvs-staging/deployments/{verified_uuid}/rollback`. It checks the response is for this staging project and requires public HTTPS/JS integrity verification, but it explicitly reports `browser_pending` even after that. It **cannot** certify the full recovery until a fresh public Chrome/F5 journey passes and a separate controlled forward restoration returns to the originally recorded SHA. A failed post-POST check may leave staging on a restored revision: the hold should remain active and the operator must recover deliberately, never silently resume automatic deployment.

Current state: hold `auto`, recovery authorization `disabled`, public rollback executor **unavailable**. There are no additional Cloudflare mutation rights, no automated recovery, and no production changes from adding these guards.

## Exact forward baseline: current canonical Pages deployment

Before any rollback, the GET-only recovery preflight must also capture the *original* active Cloudflare Pages deployment, not just its source SHA. `scripts/staradvs_forward_baseline.py` reads the owned project's `canonical_deployment` via `GET /accounts/{account_id}/pages/projects/staradvs-staging`, rejects missing/preview/dirty/failed/foreign metadata, and requires its source SHA to equal the actually served public staging release.

It then independently verifies the canonical deployment's immutable HTTPS URL with the same HTML, release manifest and actual JS SHA-256 checks used for historic rollback targets. Finally it requires an **unexpired, nonempty** trusted-main Infra verified release receipt for that canonical SHA, returning `forward_deployment_id`, `forward_immutable_url`, `forward_publish_run_id` and `forward_receipt_id` alongside `forward_sha`.

The forward baseline is a recoverable deployment **identity**, not merely a commit label. A missing canonical deployment, changed public SHA, expired artifact or mismatched immutable bundle must block the plan. This remains a read-only audit; no Cloudflare POST, automated roll-forward or authorization change is added. The actual mutating roll-forward path still needs a separate reviewed, manually approved transaction and public Chrome/F5 confirmation.
