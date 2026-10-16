# ShadowOps-owned Cloudflare Pages deployment — Chronicles staging

## Why move it?

Application repository `chronicles-of-matthias` continues to own its
source, CI, tests and standalone static web build. ShadowOps Infra owns
deployment to Cloudflare, public DNS, TLS readiness and later production
promotion. Chess Studio's Pages project and Cloudflare Tunnel are untouched.

## Safe adoption (not yet performed)

1. Ensure GitHub reports `main.protected=true` for ShadowOps Infra
   **and** Chronicles, with an active branch ruleset and CI.
2. Review and merge this publisher; **do not dispatch it yet**.
3. Retire the old Chronicles workflow
   `.github/workflows/pages-staging.yml` through a separate PR in the source
   repository; this prevents both repositories controlling the same custom
   domain. The owner gate refuses publishing until its deletion is on
   Chronicles `main`.
4. Configure `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as protected
   ShadowOps Infra Actions/environment secrets. Use a limited token for
   Pages and DNS writes to `shadowops.dpdns.org`, not the Chess Studio token
   if an independent one is available. A token is not fetched out of Chess
   Studio's secret store.
5. Manually run `ShadowOps · Chronicles staging Pages release` from
   ShadowOps `main`. It reads source code from current, protected Chronicles
   `main`, checks exact immutable SHA, tests the shell, and publishes only
   the `chronicles-staging` Pages project. Any advance of either `main`
   between checkout and admission aborts.
6. Demand the `CHRONICLES_PAGES_STAGING_HTTPS_OK` marker from an actual
   public TLS/HTTP check before calling staging online.

No `pages deploy` occurs during PR checks. No changes are made to
`chess-studio-staging` Pages, tunnel ingress, OCI, API, MongoDB, production,
or saved games. This is still the static staging **landing page**; extracting
the playable app is separate work.

## Why not auto-release immediately?

Ownership has not transferred yet and Infra's Cloudflare credentials must
be installed. A guarded manual first publication is safer than enabling
competing production-grade writers. After one verified deployment and
source workflow retirement, automatic main -> Pages releases can be enabled
in a subsequent small PR.
