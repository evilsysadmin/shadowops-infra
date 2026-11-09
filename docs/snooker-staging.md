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

## Exact-source admission

The independent `Snooker · verify current source main for staging` workflow
checks a *push* on `main` for its immutable SHA, successful physics/build and
real desktop/mobile Chromium steps, and the unique non-expired
`snooker-web-dist` with its GitHub-recorded SHA256 ZIP digest. Its validator
also rejects archive path traversal, symlinks, scripts outside `assets/`, huge
entries and source-supplied `_worker.js`; Infra owns the authenticated edge.

Run `python3 scripts/snooker_source_admission.py check-current` with an
independent GitHub read token to obtain a SHA/run/artifact receipt. Recheck
source HEAD immediately before any future publication. **Admission is not
deployment, authentication or an authorization to create Pages resources.**

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


## Identity service contract (default-off)

The candidate code now recognizes a `snooker` issuer audience and a pinned
staging HTTPS origin. Existing staging runtime consumers remain exactly those
provisioned in the independent Vault bundle. **No Snooker credential can be
provisioned by this increment**; the operator opt-in, Vault validation and
Pages edge service binding must follow in separately tested steps. A green
contract is not evidence of public Snooker login or staging publication.


## Explicit Snooker Identity provisioning (code path, not activation)

The protected `ShadowOps Identity · isolated staging operational handoff`
workflow now accepts `snooker_consumer: preserve | enable`. Default
`preserve` does not create the consumer. A deliberate `action=provision`,
`snooker_consumer=enable` on protected Infra `main` can append exactly one
independent `soc1_` proof to the existing staging Vault bundle; retries reuse
the same proof, preserve every other consumer and do not rotate database or
signing keys. Invalid input fails *before* cloud activity.

**Do not provision yet as an assumed consequence of merging.** The explicit
operator dispatch still needs to occur, followed by a tested Identity rollout,
separate Snooker Pages edge service binding and all-URL fail-closed smoke.
Never place the generated secret or full bundle in this repository or a log.


## Identity-gated Pages edge (not deployed)

`edge/snooker-identity-gate.mjs` is the Infra-owned advanced Pages Worker
and will be injected as `_worker.js` into the exact admitted Vite build only
during a future release. The app repository never holds the edge secret.
Unknown hosts and all `*.pages.dev` aliases return 404; the custom domain
returns an unauthenticated 401 login shell but never the app's HTML/JS/CSS.
Signed Ed25519 audience `snooker` tokens and live Identity freshness establish
a short-lived Secure/HttpOnly host-only cookie. Wrong audiences, revoked/expired
tokens and Identity outages fail closed. The independent Vault service proof
must be provisioned through the protected operator workflow and bound to Pages.

Offline tests do **not** prove Pages delivery, alias denial or an active login.
Future publication must enforce `fail_open=false` on both production/preview,
verify real deployed hashes and browser play, plus guest/revoked denial.


## Empty dedicated Pages project provisioning (manual only)

After inspecting that the `snooker-staging` project and its DNS do not belong
to another app, dispatch **Snooker · create private Pages project (manual only)**
from protected Infra `main` with the existing staging-environment Cloudflare
credentials. The workflow only creates/claims an empty dedicated Direct Upload
project and sets `deployment_configs.production.fail_open=false` and
`deployment_configs.preview.fail_open=false`, plus a public-routed HTTPS
fetch compatibility flag. A second GET confirms both settings. It does **not**
attach the custom domain, upload assets, configure service secrets or publish
any build. Missing credentials/foreign resources/unexpected settings abort.
Do not treat the empty project as a playable staging deployment.
