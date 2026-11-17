# Matthias Bridge Squad — production ShadowOps ID admission

**Requested hostname:** `https://bridgesquad.shadowops.dpdns.org/`

**Status: source-only gate / DEFAULT OFF. Not a live deployment.** The independent ShadowOps Identity HTTP application token issuer in Infra is currently staging-only. Its `StagingAppSigner` refuses production configuration and its closed audience registry does not yet contain `bridgesquad`. The `id.shadowops.dpdns.org` hostname is a production *contract*, not evidence of a running independent production service. Do not reuse `id-staging` accounts, keys, sessions, or service proofs on this production hostname.

## Strict edge contract

- Pages production project reserved name: `bridgesquad-production`, owned by ShadowOps Infra, not the game repository.
- Hostname: exactly `bridgesquad.shadowops.dpdns.org`. Unknown hosts, Pages `*.pages.dev` and preview deployment aliases get 404 without reaching assets.
- Expected JWT: Ed25519, `iss=https://id.shadowops.dpdns.org`, `aud=bridgesquad`, two-minute maximum, UUIDv4 `sub`, correct `sv`, `jti`, expiry, nbf, JWKS signing key, and live freshness RPC per request.
- Binding: `SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL`, a consumer-specific `soc1_` secret retrieved and installed by an audited Infra operator only. It must never be in the game repo, GitHub artifacts, source PRs, or browser storage.
- A verified session receives a Secure/HttpOnly, host-only, SameSite=Lax `__Host-bridgesquad` cookie. The unauthenticated root gets a separate 401 login shell, **not game assets**. Other resources and protected JS get 401/503.
- Wrong issuer/audience, revocation, missing proof, Identity unavailable or invalid JWT: fail closed. Tests use synthetic in-memory keys and fake freshness, **not a real Identity sign-in**.

## Activation checklist (not automated in this PR)

1. Obtain a separately reviewed, operational **production** ShadowOps Identity deployment with production Mongo, signing keys, session/revocation, backups and independent credentials. Confirm `/login?app=bridgesquad`, `/api/identity/token`, JWKS and freshness transport are live and the new exact-origin audience is explicitly admitted.
2. Add `bridgesquad` to the production issuer's closed audience registry. Provision a unique production service proof via protected Vault/OCI operator procedures; never borrow another consumer's proof.
3. Audit all existing DNS/Pages entries. Explicitly refuse foreign/mismatched records and unexpected Pages aliases. Create a dedicated Cloudflare Pages project only through trusted Infra credentials. Deploy the reviewed edge Worker alongside a source-SHA-pinned copy of `index.html`, never anonymous static-only Pages.
4. Bind the app-only proof in the Pages **production** configuration, deny anonymous asset requests and all preview/production Pages aliases, and enable fail-closed on every route. Add the custom DNS only after readiness.
5. Live E2E: unauthenticated deny of root, HTML, assets, HEAD, and Pages aliases; actual account login, session renewal, logout and revocation; cross-audience/cross-environment negatives; separate account-local game progress; current main source SHA on mobile and desktop.
6. Retire any prior publicly accessible `evilsysadmin.github.io/matthias-bridge-squad/` deployment at cutover. A login on the custom domain is not protection if static content remains publicly served elsewhere.

This PR does not mutate Cloudflare, DNS, OCI, Vault, Identity runtime, or production. Do not claim the requested hostname live on the strength of these unit tests alone.
