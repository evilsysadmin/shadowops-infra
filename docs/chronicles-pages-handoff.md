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

## First protected-main publication

The independent OCI web container passed its **local** smoke on the shared A1
([run 38903782258](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38903782258)).
It listens only on `127.0.0.1:18082`, not the public HTTPS endpoint.

Because Chess Studio still reconciles the existing A1 Cloudflare Tunnel,
adding Chronicles ingress there would create two competing tunnel writers.
This bootstrap instead publishes the **character-forge static preview** to
Chronicles' isolated Cloudflare Pages project; the OCI container stays private.

Merging the reviewed Pages workflow to protected ShadowOps `main` triggers
one guarded publish through a `push` event. Later source-only updates still
require `workflow_dispatch`, until we add a separately reviewed source-sync
mechanism. The job checks protected current SHA of both repositories, absence
of the retired source-side Pages publisher and actual shell tests. Before any
Cloudflare writes it performs a GET-only exact-hostname DNS/Pages preflight;
any foreign tunnel/Pages owner aborts without overwriting the record.

Missing Cloudflare secrets, unavailable domain ownership or missing managed
TLS also fail closed. **Do not claim public readiness** until the workflow
prints `CHRONICLES_PAGES_STAGING_HTTPS_OK` after real HTTPS verification.
This is still the character forge, not the full game.


## Parallel React Vite preview (non-production migration gate)

The Cloudflare Pages project now serves two deliberately distinct surfaces
from **one protected, SHA-pinned source checkout**:

- `/` stays the existing static forge and authored crypt explorer; it is the
  known-good visual rollback and retains all prior HTTPS/JS smoke markers.
- `/react/` is built inside ShadowOps from the original Chronicles React app
  in `frontend/`, using `CHRONICLES_DEPLOY_BASE=/react/`. It contains the
  original migrated character creator and Chronicle journal while core 3D,
  combat, saves and authentication still await migration.

The publisher installs only declared Node dependencies from that checkout,
tests original React source, builds the Vite bundle, and copies
`web/` plus `frontend/dist/` into a distinct temporary Pages root.
No cloud credentials are exposed to the source repository, and no files under
Chess Studio or the production hostname are modified.

The release is not green unless the old root, existing explorer ES modules,
React HTML at `/react/`, and its hashed JS **and** CSS URLs all return
HTTPS 200 with correct content types. A 200 HTML fallback for JavaScript
must fail the release. No WAF/TLS bypass or mock gameplay is permitted.
Cloudflare Pages remains owned solely by ShadowOps Infra.

**Do not redirect `/` to React** until the original first-person 3D renderer,
actual engine, character sheet, initiative, quest content, API parity and
owner-scoped persistence pass real browser smoke tests.

## Original Swordhaven 3D parity milestone

Source Chronicles PR #68 brings the **unaltered** Swordhaven Three.js scene
builder and MM3 pixel-texture generator into the independently built React app.
The protected Pages release validates that the compiled `/react/` bundle
actually contains the original `swordhaven-sky-dome` and
`chronicles-swordhaven-town` geometry markers, in addition to previous HTML,
JS, CSS and canonical portrait tests.

The view is opened from the React Home via **Recorrer Swordhaven original en 3D**.
It is still an isolated first-person **visual walk** of the actual geometry
and actual walkable city grid, not the full Chronicles gameplay engine.
Real browser WebGL appearance still requires manual/visual smoke beyond CI's
public HTTPS/static asset verification; never call the full game migrated
based on the source or release gate alone. Leave root `/` fallback unchanged.

## Swordhaven phone layout release

The source PR [chronicles-of-matthias #69](https://github.com/evilsysadmin/chronicles-of-matthias/pull/69)
corrects the first public mobile screenshot: formerly a long scroll page
with a small canvas, giant narrative, oversized controls and the party below
the first viewport. The new independent React `/react/` Swordhaven screen
uses a viewport-height game composition, full flexible 3D canvas,
compact compass/narration overlays, two-row touch controls, four portraits
and a disclosure for migration limitations. The authentic original 3D
geometry and 19x19 collision runtime are unchanged.

The source workflow now builds in Chromium with WebGL, checks 360/390/430 px
portrait and 844×390 landscape layouts, verifies controls/party/canvas
visibility, avoids both horizontal and vertical overflow, exercises
movement/restart, and retains real screenshots as CI artifacts. This
supplements, rather than replaces, the protected Pages owner/HTTPS smoke.
This infra release requires the distinctive new UI classes to be present
in the published React bundle while preserving the old `/` rollback.

## Screenshot-reference Swordhaven HUD promotion

Chronicles source PR #70 (source `main`, after all 5 workflows green and
four real Chromium/WebGL mobile E2E cases passing) moves from a document-style
screen to one full-screen original Three.js Swordhaven view with diegetic
overlays in portrait and landscape. The real 19×19 walk grid drives an
explored-only minimap, and the original Chronicle modal opens with J or an
in-world button. The menu only exposes implemented actions; no invented HP,
monsters, shop state or attack buttons. Original root `/` remains a
known-good rollback; React remains only under `/react/`.

The Infra build now requires markers for the minimap, Chronicle and floating
HUD in **actual compiled Vite JS/CSS**, plus the previous Three.js and
static root checks. Browser viewport tests live in the source workflow;
ShadowOps continues owning only the protected Cloudflare Pages release and
live HTTPS smoke. Treat this as **HUD layout progress** not complete gameplay.
