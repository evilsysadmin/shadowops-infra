# Star Adventures · server-side Identity gate (source candidate, not deployed)

`edge/staradvs-identity-gate.mjs` is an **Infra-owned candidate** Cloudflare
Pages Worker. It is deliberately NOT wired into the existing public static
Star Adventures staging publisher and does not change Cloudflare/OCI/DNS.

The Worker accepts only `staging.staradvs.shadowops.dpdns.org`; every
`*.pages.dev` hostname returns 404. The canonical anonymous root serves a
401 ShadowOps ID login shell. HTML, the `/bridge` game deep link, JS, CSS,
`release.json` and other resources all require a verified JWT plus a fresh
service-to-service Identity check before the Pages ASSETS binding is invoked.
The separate `staradvs` audience, staging issuer, UUIDv4 subject, Ed25519
JWKS signature, time bounds, session version and token JTI are enforced.
Missing proof, revoked session or unavailable IdP fail closed. The app-only
proof binding is `SHADOWOPS_STARADVS_SERVICE_CREDENTIAL`; do not copy the
Identity operator bundle to Pages or commit a credential to the game repo.

Test locally with:

```sh
node --test tests/staradvs-identity-gate.test.mjs
node --check edge/staradvs-identity-gate.mjs
```

The unit tests use synthetic signed tokens and mock identity freshness; they
do NOT prove a live login or current public Pages denial.

## Strict activation prerequisites

1. Merge separately reviewed `staradvs` staging audience source and deploy the
   current isolated staging Identity with that audience explicitly provisioned.
   Keep every production account, signing key and service secret independent.
2. Build the admitted exact Star Adventures game SHA under Infra only, then
   package this Worker together with its public login/bootstrap shell. Keep
   `ASSETS` available only after authorization and bind the single app-only
   `soc1_` proof securely in the exact Pages project.
3. Update the existing `staradvs-pages-staging.yml`, its release/integrity
   verifier and its public-browser workflow **in the same controlled release**
   to verify guest denial (GET, HEAD, assets, /bridge, /release.json) followed
   by real signed-in play, refresh, logout, revocation, cross-audience
   rejection and immutable Pages alias denial. The present verifier expects
   anonymous 200 and is therefore incompatible with the protected rollout.
4. Verify the exact Cloudflare project, existing DNS ownership, release SHA,
   successful app login, alias inventory and rollback. Do not claim the game
   protected based on a green synthetic test or the unmodified static
   publisher. Keep legacy public aliases and older Pages deployments in the
   cutover inventory.

An anonymous 401 protects the canonical game only when it is **actually
served from the deployed Worker** and bypass aliases are also denied. This
candidate alone changes none of those live routes.


## Static-publisher containment while Identity cutover remains incomplete

The existing scheduled/push/manual staging Pages workflow is now **paused
before source admission or any Cloudflare write** by the new
scripts/staradvs_protected_bundle.py gate. Its reviewed source policy
config/staradvs-protected-release.json has only one accepted value:
mode=pending-identity. No environment variable, workflow dispatch input or
same-source-SHA shortcut enables releases. A future cutover must be a
separately reviewed code change, replacing the public-200 release/browser
checks with anonymous denial and real account E2E.

The protected package builder first requires an already verified immutable
game JS manifest, copies the **exact** Infra-owned Worker into dist/_worker.js,
and records the staradvs audience/issuer in release metadata. It rejects
missing/mismatched Worker bytes, source SHA drift, tampered JS, symlink assets,
_routes.json, and conflicting Pages Functions. The Worker is executable Pages
Advanced Mode code; metadata is descriptive, NOT an access-control boundary.

The release command also requires the policy gate and verifies the private
bundle immediately before Wrangler. Infra revision pinning now includes the
edge/staradvs-identity-gate.mjs source; an edge security change invalidates
older publication candidates.

**No Cloudflare resource is changed by this PR.** The previously published
static site and historic immutable deployment aliases may remain public until
an independently verified protected cutover. Pausing new static releases is
containment, **not** proof that current URLs are protected.
