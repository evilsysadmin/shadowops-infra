# Snooker of Matthias — Cloudflare Pages staging onboarding

Staging hostname: **https://staging.snooker.shadowops.dpdns.org**.
Source: **evilsysadmin/snooker-of-matthias**.
Infra owns dedicated Direct Upload Pages project **snooker-staging**, zone DNS,
Identity audience, protected staging credentials, publication and rollback.
This first infra iteration is **read-only**: it neither provisions, deploys,
grants access nor certifies that any Cloudflare asset is already present.

## Evidence and boundaries

- Source PR #1 is merged; the game builds `snooker-web-dist` and real desktop/mobile
  Chromium screenshots in its own CI. Green source CI is not a deployment.
- Source PR #2 adds hold/release Space power and viewport fitting. An exact
  green *main* SHA must be re-admitted before a future release.
- ShadowOps Infra issue #527 tracks activation: https://github.com/evilsysadmin/shadowops-infra/issues/527
- No backend/DB/VM/R2 is needed for this Three.js/Vite POC.
- No public staging/guest mode. All custom-host, production `pages.dev` and
  preview aliases must **fail closed** for anonymous/revoked sessions, wrong
  Identity issuer/audience and unavailable Identity.

## Read-only preflight

On PR, run the offline tests (no secrets required).
On protected Infra `main`, workflow **Snooker · staging Pages read-only inventory**
uses existing staging-environment Cloudflare credential custody to GET the exact
zone, Pages project, custom-domain and DNS identities. It *never* makes a
Cloudflare write or prints API tokens. It rejects foreign/mismatched project,
other-source integration, wrong Pages branch, unexpected aliases/custom domains,
duplicate DNS or nonproxied/wrong-target records.

```sh
python3 -m unittest discover -s tests -p test_snooker_pages_readiness.py -v
python3 scripts/snooker_pages_readiness.py plan
# Only inside a trusted staging operator environment with read credentials:
python3 scripts/snooker_pages_readiness.py inspect
```

An inventory receipt only means ownership was classifiable, **not** that
authentication works. Missing Cloudflare credentials stop the workflow
without creating anything.

## Subsequent incremental release gates

1. Prove exact current green game `main` SHA (unit/build/Chromium) and verify
   immutable dist artifact digest and safe extraction, not an unverified URL.
2. Explicitly register audience `snooker` in staging ShadowOps Identity only.
   Gate all Cloudflare edge entry points including Pages preview aliases;
   strict issuer/signature/audience/freshness, fail closed on revoked sessions.
3. Provision and/or claim only the dedicated project and proxied custom host,
   refusing all unexpected foreign DNS/Pages resources.
4. Publish a source-SHA-pinned, authenticated release through Infra using
   existing protected credentials, rechecking exact source/owner revision before
   any Cloudflare mutation.
5. Verify signed-in game/WebGL and 200 responses, anonymous/wrong-audience/
   revoked/Identity-down denial on domain and Pages aliases, desktop/mobile
   screenshots, immutable release receipt and rollback.

No unrelated Football, Chronicles, Chess, Portal or production resources may
be changed by Snooker onboarding.
