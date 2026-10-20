# Chronicles staging — current release and recovery runbook

Updated: 2026-10-20. This is the **current** operational entry point for
`chronicles-of-matthias` staging. The older
[`chronicles-pages-handoff.md`](chronicles-pages-handoff.md) records the
migration history, including obsolete `/react/` and manual-bootstrap stages;
do not follow its historical instructions as if they describe today's pipeline.

## Ownership and boundaries

- `evilsysadmin/chronicles-of-matthias` owns game source, CI, frontend build
  inputs and API image.
- `evilsysadmin/shadowops-infra` alone owns staging deployments: isolated
  OCI API, Cloudflare Pages `chronicles-staging`, DNS/TLS verification and
  release artifacts. Nothing here authorizes changing Chess Studio or
  promoting a staging SHA to production.
- Infra receives source-CI dispatches when configured and also polls hourly.
  Changes to this file are a **release request**, not proof of deployment.

## Staging state machine

1. **Source CI ready:** all three required Chronicles source-main checks
   succeeded for one immutable, current SHA. An older or pending SHA must
   not be published merely because its CI was green in the past.
2. **API verified:** the OCI deploy finishes public health and player-path
   smoke, then writes `chronicles-api-staging-<SOURCE_SHA>`. Pages checks the
   exact API artifact, its completed successful Infra API workflow run on
   `main`, **and** the current public `/health` and `/ready` endpoints
   before starting Pages work. A degraded API blocks Pages mutation even
   when a valid historical API receipt exists.
3. **Pages verified:** Pages publishes the exact SHA (or, if the exact SHA is
   already live, retries public checks **without** rebuilding/redeploying).
   It checks custom-domain HTTPS, public `release.json.build`, desktop/mobile
   Chromium and the real login/first-hour browser journey, then rechecks that
   Chronicles source `main` has not advanced.
4. **Receipt:** only after these checks does Infra upload
   `chronicles-pages-staging-<SOURCE_SHA>` with `source-sha.txt` and
   `evidence.json`. Evidence includes the live manifest, linked API receipt,
   the workflow run and `verification_mode` (`new_publish` or
   `existing_live_build`).

A green PR, skipped deployment job, successful dispatch, or historical
artifact alone does **not** establish current public staging readiness.

## Recovery without unnecessary mutations

- **Nothing new:** verified Pages receipt **plus matching public** manifest
  skips rebuilding; the API skips only with a trusted receipt **and** live
  public `/health` and `/ready` responding (with one retry per endpoint).
  Check the actual run before claiming a deploy happened.
- **Trusted API receipt but public health fails:** the API admission fails
  closed and leaves the deployed container untouched. The staging watchdog
  reports persistent public failures. Investigate before a deliberate manual
  redeploy; a single timeout is not grounds for automatic mutation.
- **Pages artifact missing but correct SHA already live:** the next admitted
  Pages staging run skips build/Cloudflare mutation, repeats public smoke, and
  issues a verified receipt only on success.
- **Live manifest differs from current green source SHA:** the admission path
  is allowed to republish the current SHA, provided the exact API prerequisite
  and ownership gates hold.
- **Source advances mid-run:** pre-mutation, immediately pre-Wrangler and
  post-smoke guards block an obsolete Pages receipt. A new admitted run must
  validate the newer SHA.
- **API artifact missing, CI pending, Cloudflare ownership conflict or
  smoke failure:** treat as **not verified**; inspect the failing gate. Do not
  manually manufacture a receipt or assume retries succeeded.

## How to verify a release

Review the actual workflow runs in
[ShadowOps Infra Actions](https://github.com/evilsysadmin/shadowops-infra/actions):

- `ShadowOps OCI · Chronicles API` — requires the exact-SHA API receipt and
  successful public/player-path smoke.
- `ShadowOps · Chronicles staging Pages release` — requires the exact-SHA
  Pages receipt, successful live HTTPS manifest check and browser smoke.
- `Watch Chronicles staging health and release drift` — reports persistent
  public health/release drift, not a new deployment.

For an independent read-only manifest check:

```bash
curl -fsS 'https://staging.chronicles.shadowops.dpdns.org/release.json' \
  | python3 -m json.tool
```

Compare its `build` to the **actual current Chronicles source main SHA**
and the SHA suffix of both trusted release artifacts. A manifest match alone
does not prove that the API or browser smoke completed successfully.

## Manual versus automatic operation

`workflow_dispatch` with manual force/redeploy retains the explicit
republication behavior; automatic/`only_if_new` requests are idempotent.
Promotion to production is separate, manually authorized and requires an
explicit vetted SHA. Never interpret a staging receipt as production approval.

Previous release-request SHA notes live in this file's Git history; they
are historical requests, not an instruction to redeploy those revisions.
