# ShadowOps Universe — standalone root-domain portal

This is the independent, static portal for the eventual `https://shadowops.dpdns.org/` root. It does **not** deploy Chess Studio, Chronicles or Star Adventures. Game repositories and existing Cloudflare resources remain untouched.

## Develop

```bash
cd portal
npm install
npm run check
npm test
npm run dev
npm run build
```

Node 22+. The build is a static `dist/` directory intended for a **dedicated** Cloudflare Pages project, separate from any game's Pages project/tunnel. The Vite base is `/`: preview at a dedicated hostname, not at a path prefix.

## Catalog and safe navigation

`src/catalog.mjs` contains the only outbound launch destinations. The Chess Studio and Chronicles root URLs are provisional/external and explicitly **not** asserted live. Star Adventures is a non-clickable coming-soon entry until it has a separately verified deployed URL. The future catalog already reserves Pawn Trailblazer, Football and Tactics.

Links are always visible in plain semantic HTML and work when WebGL is disabled. WebGL is progressive enhancement, not a gate to launch. Keyboard, pointer, reduced-motion, tab visibility and limited mobile pixel ratio are handled separately.

## Art direction and performance gates

The first interactive scene is a bespoke, smooth-shaded observatory with atmospheric portals, physically based materials and a shader-driven inner veil; not low-poly boxes. This is **technical art staging**, not acceptance of the final premium artistic bar.

Before publishing on the root, add authored high-quality GLB scene assets with provenance/license documentation, baked or compressed textures (KTX2), mesh compression (Meshopt/Draco), tasteful lighting and photographic-level materials. Keep a measured GPU/render budget and screenshot acceptance checks for desktop and 360–430 px mobile. Heavy assets belong on a CDN, not directly in Git history. Do not add a new scene that looks like a collection of primitives just to ship something.

## Explicitly deferred: public rollout and Chess Studio ownership

1. Build+test the portal in this repo, preview with a **new isolated** Pages project and hostname.
2. Verify the root-domain DNS record and its actual owner using Cloudflare **read-only inventory**, with before/after route checks.
3. Perform the root Pages-domain claim only when accepted by the owner; never silently mutate existing game DNS/Tunnel mappings.
4. **Separate future iteration:** Chess Studio OCI/Cloudflare/Render handoff to ShadowOps Infra, with a single reconciler, route-preservation tests and rollback. This portal PR does not transfer that ownership.

No production secrets in PR CI. A green build is **not** evidence of a real root-domain deployment or visual-art acceptance.

## Automated browser visual evidence

```bash
cd portal
npm install
npx playwright install chromium
npm run test:browser
```

Portal CI runs headless Chromium at 360/390/430/1440 px with a fresh
static 3D scene (when WebGL is supported), an explicit no-WebGL fallback,
keyboard-only selection, a failing WebGL-module request, and an overflow gate.
Screenshots of all sizes are uploaded as a temporary workflow artifact.
These screenshots make art review possible; they **do not** certify the
result as premium. Final visual acceptance requires a human comparison
with approved art, and physical GPU verification remains a separate gate.

To prevent heavy WebGL from gating navigation, the Three.js chunk is
loaded only after the scene enters the viewport. The game catalog is
always ready first; a missing 3D device only switches the presentation.

## Vistas temáticas (estudio artístico)

The observatory uses **three different procedural material studies**, not one recolored noise curtain: a silhouetted golden chess throne with perspective flooring, a torchlit receding dungeon, and a planetary starship observation pane. The shared gallery now has a stone backdrop, structural arch ribs, bronze detailing and a perspective floor. These assets remain technical studies: **do not declare the 3D visual quality premium until authored GLB art and physical GPU screenshots are reviewed**. The game routes, root DNS, and Cloudflare owners remain unaffected.

## Architectural material pass

Stone surfaces now use seeded, generated albedo, tangent-space normal and roughness maps; backdrop niches, instanced voussoirs, and a restrained lighting scheme give the three entrances actual depth. They are material studies, **not a substitute for licensed production GLB art**. Chrome CI checks WebGL shader errors, screenshots at 360/390/430/1440 px, and a conservative render-budget contract (under 86 draw calls and 260K triangles). No Cloudflare/OCI/Render mutation.

## Power-conscious cinematic interaction

The world-focus change now pans the camera only subtly and respects reduced-motion immediately. The renderer runs at **up to** 45fps desktop/30fps mobile and halts its rAF chain when the tab is hidden **or the 3D canvas scrolls fully offscreen**. On return to the viewport it repaints and resumes without losing the selected world, and reduced-motion mode continues to render only on demand. Frame scheduling does not confuse rAF timestamps with a force flag. The WebGL screen remains optional and root DNS ownership is unchanged.

## First authored GLB object / build-time pipeline

`art/build-armillary.mjs` is the source master of a small celestial armillary instrument. It exports a fully indexed GLB 2.0 with three merged PBR primitives and a SHA-256 content-addressed filename. The artifact is generated by `npm run art:build` (automatically before `dev`, `build` and unit tests), never committed as a binary: `public/art/armillary-*.glb` and `src/armillaryAsset.generated.mjs` are outputs. Desktop loads the model lazily with Three.js GLTFLoader, while mobile and no-WebGL skip it; a failed optional asset must never block the game catalog. The authored geometry is **a first pipeline pilot**, not final approved cinematic GLB environment art. Larger production assets will live in an independent CDN/R2 manifest with provenance and measured GPU cost.

## Three world-specific authored GLB reliefs

The art source in `art/build-relics.mjs` adds three different sculptural emblems (`relic-chess`, `relic-chronicles`, `relic-star`). Each has original geometry, its own three PBR primitives, an independently SHA-256 addressed GLB asset and a per-file size/triangle gate. The browser imports these only on desktop after the scene becomes interactive; mobile does not download them. The generated JS manifest is deliberately gitignored. These are restrained architectural details — **not** the final AAA-quality authored gallery, which remains gated on #153.

## Authored architectural GLB pilot

`art/build-gallery-frame.mjs` now authors one SHA-256-named GLB for the common three-bay façade (arches, dressed stone keys, shafts and cornice). The runtime no longer builds those procedural meshes on the successful path; instead it asynchronously loads a three-primitive PBR sculpture. If the GLB fails, the preceding procedural construction is retained as a fallback. Unit tests validate the binary and size, and Playwright exercises both real loading and the deliberate network-failure recovery. This remains a parametric source-authored intermediate—not a signed-off Blender environment or final CDN rollout; #153 still tracks those acceptance gates.

## First Blender-authored environment component

`art/blender/celestial_vault.py` is original source art for the observatory's upper vaulted nave, brass relief and central astronomic oculus. It exports GLB 2.0 in headless Blender, joins individual modeled elements by PBR material, and produces a SHA-256 content-addressed asset and generated URL manifest through `art/build-blender-vault.mjs`. CI installs Blender and sets `REQUIRE_BLENDER_ART=1`, exercising real loading on desktop/mobile and a deliberate network failure. Local dev without Blender gracefully omits only this optional ornament; published builds **must** require Blender to avoid silently losing it. This is the first DCC-authored environment object, still a controlled iteration rather than sign-off for the full premium scene (#153). Existing DNS/Pages/Render/OCI are untouched.

## Blender forecourt and compass-rose marquetry

The original `art/blender/celestial_vault.py` now models the approach paths (9 low-profile basalt inlay slabs), hand-laid brass seams and a restrained compass rose directly into the **existing** vaulted-environment GLB. It does not add a network request, PBR material, draw call or interaction surface. The GLB geometry test asserts low foreground Y and positive foreground Z, and the runtime bounding-volume check rejects a misoriented or clipped floor. The asset remains optional at runtime with the catalog unaffected. This is still an incremental architectural artwork, not a final art sign-off; physical GPU / premium gallery #153 remains open.

## Lateral wall bays in Blender

Two original recessed lancet niches with double-depth stone and brass archivolts, a layered astrolabe and shallow horizon engraving replace visually empty lateral wall stretches. Everything remains merged into the existing three PBR material meshes and the existing vault GLB; it introduces zero extra HTTP requests, draw calls or interactive hit surfaces. Torus/cylinder segment counts for tiny decorative elements are reduced from 96 to 64 to preserve the strict 1.5MB source-art budget. The portal still functions when this optional GLB fails. This is an incremental art study, not final approved premium DCC architecture (#153).

## Architectural grazing lightmap

`galleryArchitecture.js` now uses an entirely deterministic, 256×128 RGBA emissive texture to **gently graze stone around the six side jambs and three upper arch crowns**, in restrained brass/ember/moon-blue tones. Only the existing rear-wall draw receives it: no new meshes, shadow maps, lights, GLBs, files fetched, or per-frame animation. It has a 128 KiB CPU/GPU texture budget and a Node test for color direction, falloff, bytes and bounded brightness. The foreground, floor, portals and no-WebGL/failure navigation are unchanged. This is a material study, not final approved Blender PBR/texturing (#153).

## Carved inter-arch masonry

The original Blender vault source now adds four genuinely three-dimensional stone infill panels behind the structural pilasters and between arch openings. Each uses a smooth 10×20 hand-shaped mesh with tapered edges, shallow mineral grooves and bounded subcentimetre relief, sharing the existing stone PBR material and the same three-material GLB. Unlike a planar decal, these surfaces respond to camera parallax and grazing light. No new material, mesh draw call, CDN request, interaction plane or dynamic light is added. The 1.5 MB GLB budget, responsive Playwright screenshots, geometry limits and deliberate fallback tests remain required. Full premium texture authoring and GPU-hardware certification remain deferred to #153.

## Runtime routing by portal domain (staging vs production)

The **same static built artifact** runs at both Pages origins; route selection is based only on the exact browser hostname, never a query flag or a build-time environment. `staging.shadowops.dpdns.org` links to Chess Studio, Chronicles and Star Adventures **staging**; `shadowops.dpdns.org` links to the corresponding production games. Star Adventures remains disabled in production until a separately verified production deployment exists. Any other hostname (including localhost or a Pages preview) disables external launch links rather than unexpectedly sending users to production. Both the semantic game links and the WebGL-enhanced catalog share this resolver; tests cover destinations and browser behavior under both virtual deployed origins. DNS and the games' deployment ownership are unchanged.

## Visible environment identity on mobile

At 360–430px the standard masthead tagline is intentionally hidden, but staging and preview now show a short, accessible **STAGING** / **PREVIEW** identity beside the brand. Production remains uncluttered. Staging world CTAs say `Entrar · staging ↗` and expose a destination-specific accessible name; production CTAs retain `Visitar mundo ↗`. The environment cannot be set via query string: it still comes solely from the exact browser hostname. Responsive Playwright coverage verifies both destinations, visible mobile identity and no overflow without WebGL.

## Stratified slate material study

The shared gallery stone now uses deterministic multiscale mineral layers, irregular quiet bedding, a restrained iron/mica tint and tangent-space normal/roughness variation. This **replaces**, rather than adds, the three existing 256×256 stone PBR textures. Crucially, the separately baked 256×128 warm/cool grazing lightmap remains in place, preserving local illumination under the portals. No additional meshes, draw calls, network downloads or light sources are introduced. Unit tests enforce exact texture byte budgets, repeatability, material ranges and the unchanged grazing illumination; Chromium screenshots remain the visual review gate. This is interim art pending physical GPU and final material acceptance in #153.

## Diegetic gateway focus, without accidental navigation

On desktop, hovering a catalog world temporarily focuses the corresponding 3D portal; keyboard focus does the same, including when reduced motion is requested. Pointer exit or keyboard blur restores the actually selected world. This visual preview never rewrites the selected detail panel, its `aria-pressed` state, or its environment-specific launch URL: only click/tap/keyboard activation commits selection. Touch pointer-enter alone does not trigger hover. The behavior works with the existing offscreen GPU pause, optional WebGL, and no-WebGL semantic fallback.

## Previewing the 3D gateways directly

The observatory's existing raycaster now previews the portal beneath a mouse or pen cursor. Its portal shader/rim/light focus changes without committing selection, changing `aria-pressed`, or rewriting a world destination. Moving off the canvas returns to the catalog's hover/keyboard focus (or the selected game). Touch pointer movement and active camera dragging never trigger a preview. Clicking a glass pane remains the only 3D selection action. This reuses the preexisting three glass hit targets, with no extra geometry, GPU passes, network requests or per-frame picking; browser QA verifies hover, leave, keyboard precedence, drag cancellation and click on the real WebGL canvas.

## Primary-pointer activation safety

A gateway only commits selection when the same **primary** pointer begins and ends the short tap/click gesture on the canvas. Right/middle mouse buttons, pen barrel clicks and secondary touch pointers do not launch or select a world; dragging still has its movement threshold. Pointer leave/cancel resets the gesture. Playwright covers an actual touch-enabled 390px canvas tap, a synthetic nonprimary touch and desktop right/left-click behavior. Hover remains mouse/pen-only and non-committing.

## Scene hover cue

When a desktop mouse/pen points at a glass gateway, the observatory's **existing** lower scene caption briefly identifies the world and says “Clic para explorar”, using the world accent color. The caption is visually subtle, non-interactive, and not an extra live announcement; the authoritative, keyboard-accessible game information remains in the catalog. Pointer leave, drag and actual selection restore its original guidance. No WebGL restores the dedicated accessible-catalog explanation. Mobile hides this hint as before and relies on touch selection. No new overlay obstruction, geometry, shader, light, request or texture.

## Pointer-picking cost

Raycast hit testing is now performed on pointer move only for hover-capable mouse/pen motion without pressed buttons. Touch movement, panning and active camera drags skip redundant picking entirely; pointer release still performs the exact glass-pane hit test needed for deliberate selection. This preserves the tested touch tap, desktop click, contextual hover hint, drag suppression and no-WebGL fallback without introducing a per-frame picker or GPU work.

## Consistent 3D gateway activation

A pointer gesture can select a world only if its **primary pointerdown and pointerup hit the same glass pane** and displacement remains under the existing 7px click threshold. A short edge swipe from stone onto glass (or between panes) must not activate a destination; normal click/tap still works. This uses one pick per pointer press and one per candidate release, while retaining the preceding optimization that skips picking on touch movement and drags. The real-canvas browser regression finds an actual gateway boundary and verifies both rejection and a valid click.

## Reproducible rendering evidence (opt-in)

To collect a bounded, local performance snapshot, open the portal with `?portal_perf=1`. Only this explicit opt-in times **JavaScript CPU submission around Three.js `renderer.render()`**, retaining the last 120 drawn frames. The scene's DOM element exposes `document.querySelector('.stage').portalPerfSnapshot()` in the developer console, reporting median/p95 submission and actual drawn-frame spacing, CSS viewport size, canvas backing resolution/pixel ratio and Three.js renderer draw-call, triangle, texture **count**, and geometry **count**. No samples are sent to a server or saved in persistent storage; the hook is absent during normal visits and removed on destroy.

CI captures these data for animated **390px and 1440px** scenes, including actual Blender GLBs, as JSON attachments in the existing Playwright visual-evidence artifact. Run locally via `npm run test:browser -- -g 'render evidence'`; on a Linux desktop one may use `npx playwright test --headed -g 'render evidence'`, verifying the browser's active GPU separately. Performance timings on shared, virtualized, or headless CI runners are **diagnostic observations, not stable timing thresholds**. The JavaScript submission and drawn-frame interval fields are **not GPU times or GPU memory bytes**; WebGL counts and canvas pixel count are resource proxies only. An independently labelled optional GPU timer is described below. Physical GPU profiling on representative devices, VRAM/texture byte inspection and premium art acceptance remain open in #153.

## Moonlit basalt plinth material study

The upper circular platform remains a metal-inset dais with warm/cool portal light pools: a first visual test replacing it with matte stone **was rejected** because it flattened the illumination. The final study only moderately raises the luminance of the lower basalt ring and the existing shared dark-metal material, preserving the highlights. Geometry, meshes, shader type, texture count, lights, camera, collision/touch surfaces and draw-call count remain unchanged. The 1440/390px screenshots must be reviewed against main after this refinement. This is a small legibility test, not final premium material sign-off (#153).

## Hardware GPU time: optional asynchronous WebGL2 query

With `?portal_perf=1`, the local `document.querySelector('.stage').portalPerfSnapshot().gpuTimeMs` field uses the browser's optional **`EXT_disjoint_timer_query_webgl2`** extension. It measures GPU elapsed execution of the Three.js drawing commands with asynchronous begin/end/query polling. No `gl.finish()`, synchronous readback or busy-waiting is used. Maximum two unresolved queries and 120 retained results; completed query objects are reused. Every GPU-disjoint event invalidates previous observations instead of silently reporting corrupt values; teardown deletes pending queries. Normal visits never create queries.

Snapshot status is `unsupported` when the extension is absent, `collecting` while awaiting valid non-disjoint measurements, `available` when median/p95 GPU elapsed milliseconds exist, or `context-lost` after a lost WebGL context. Do **not** treat `unsupported`, `collecting` or `context-lost` as zero milliseconds. GPU query execution may still have diagnostic overhead, so compare consistent opted-in runs.

For a real GPU acceptance session on a local machine: enable browser hardware acceleration, verify that WebGL actually uses the intended GPU (for Chromium see `chrome://gpu`), open the portal with `?portal_perf=1`, scroll the observatory into view, then inspect the snapshot in DevTools after the scene and GLBs load. Record the precise device, driver, browser, viewport, display scaling, WebGL renderer, extension status, GPU median/p95, draw calls and triangle counts, and compare mobile/desktop profiles. A headless CI browser can report real timings for its *software/virtual GPU*, but those values **cannot certify physical hardware**, physical GPU memory, thermals or sustained battery cost. No telemetry leaves the browser and no permission to access the user's device is implied. Issue #153 remains open until representative physical devices have been profiled.

## Repeatable local GPU capture on Linux/desktop

A human-driven session no longer needs copy/paste from DevTools. From the `portal/` directory, with Node 22+, **Blender available for the full authored vault GLB**, Playwright Chromium installed and a desktop display:

```bash
npm install
npx playwright install chromium
npm run dev -- --port 4173
# In a SECOND terminal in portal/:
npm run profile:gpu
```

The separate `npm run profile:gpu` process launches **headed** Chromium (no forced software rendering), opens the local portal with `?portal_perf=1`, waits for the authored gallery/vault GLBs and at least 45 drawn-frame samples at both 390px and 1440px, and writes **only locally** to the Git-ignored `.gpu-profile/` directory: `gpu-profile.json`, `portal-390.png` and `portal-1440.png`. The profile includes browser/rendering identifiers, optional GPU query status, CPU submission and drawn-frame interval statistics and Three.js resource counters. It never uploads diagnostics.

The target defaults to `http://127.0.0.1:4173/`; for an explicit alternate portal origin set `PORTAL_PROFILE_URL`. To select the output directory, set `PORTAL_PROFILE_DIR`. The script requires a graphical desktop session and a reachable portal; it does not silently start a server or change Cloudflare routes. The supplied 390px viewport is still a **desktop browser emulating a narrow width**, not a physical phone.

The report labels suspected SwiftShader/llvmpipe/software renderers `not-qualified`, and GPU query `unsupported` or `collecting` likewise cannot qualify. Even valid samples on an apparently physical renderer are merely `review-required`: inspect `chrome://gpu`, actual GPU/driver, thermals, VRAM and sustained mobile/desktop frame pacing before accepting art against #153. Headless/shared CI does not run this physical workflow. No automated test can certify real mobile device performance.

## Sculpted fluted stone pilasters

The four plain shafts between the portals are now actual **twelve-flute chiseled stone** in the existing authored gallery-frame GLB. Their profile is sculpted in mesh vertices rather than simulated with CSS or a procedural color stripe; two very restrained aged-brass collars per shaft meet the original bases and capitals. The four shafts and collars remain merged into the exact same **three original PBR material/draw primitives**, with no additional GLB download, dynamic lights, shader passes, raycast surfaces, runtime interactions or game links. A geometry unit test checks measurable radial relief and a low triangle count; GLB size/triangle gates and real 390/1440 screenshots remain mandatory. This is one incremental architectural refinement, not final premium-art certification (#153).

## Celestial compass: physical nautical-degree marquetry

The original inset eight-point floor compass now gains an **outside 0.962-unit brass bezel** and a single hand-authored planar mesh containing 32 radial astronomical degree graduations, with longer cardinal marks. Its star tips are raised slightly in plan (0.50 → 0.535 units) without adding height, changing walk/hit geometry or obscuring any playable portal. All additions are modeled directly in the existing Blender celestial-vault master, combined into its existing three GLB PBR primitives: no extra HTTP requests, draw calls, runtime shaders, emissive lights, textures, animation or game links. The compiled GLB test verifies a real outer-radius vertex extent and its size/triangles still must pass the 1.5 MB artwork gate. Compare actual Chromium 390px/1440px screenshots and reject if the added graduations resemble HUD clutter instead of environmental marquetry. Physical GPU and premium scene acceptance remain pending under #153.

## Atlas Chamber · isolated cinematic vertical slice

The **Atlas Chamber** replaces the three-identical-portals visual language with a new, independent design study. It is **not** the production Home and is deliberately absent from the default Vite build. Run `npm run dev` from `portal/` and open `/experiments/atlas-chamber/index.html` on that local dev server. The original `/` homepage, its catalog, game links and Pages artifacts remain unmodified. This route is intentionally a **source-only local preview**, not a second published landing page.

The first self-contained Chess Studio diorama includes a real stone/wood room, moonlit lancet window, carved library, desk, 64 physical instanced chess squares, sculpted knight and other chessmen, brass astronomical instrument, archival books and warm lamp. No downloaded assets, fake launch links or external fonts; Chronicles and Star Adventures remain intentionally unavailable seals until their dioramas are worthy. The engine respects reduced motion, sleeps when hidden/offscreen, caps rendering at 30/36fps, limits DPR, exposes render counts to local browser QA, and cleans GPU resources on unload. The environment-aware Chess Studio action uses the same canonical portal catalog: no outbound link exists on unknown/preview hosts. WebGL failure leaves a fully readable static concept screen.

Acceptance is **not** merely green unit tests: the dedicated Playwright experiment coverage attaches 390px and 1440px full-page screenshots, checks actual lit 3D content, accessible controls, graceful no-WebGL fallback, zero horizontal overflow and bounded draw calls and triangles. Compare screenshots with the observatory before promoting this visual direction. Issue #153 and physical-GPU qualification remain open; do not treat headless Chromium as representative GPU hardware.

### Atlas Chamber: true Blender hero knight (second art iteration)

The local-only Chess Studio diorama replaces the original flat source-extruded hero knight **when available** with an original hand-sculpted moonstone horse relief: joined cheek/head volume, swept mane incisions, sculpted ears, a gold harness and eye insets over a turned base. Three merged GLB PBR primitives are generated from `art/blender/atlas_knight.py` with `npm run art:build`. The content-addressed result and the generated manifest live under the experiment and `src/*.generated.mjs` respectively; both are ignored by Git. **No Atlas GLB is included in the root production Pages distribution** because this source-only experiment is not a Vite production entry and its compiled art is outside `public/`. The same generated experiment files pass via a GitHub Actions artifact to the browser QA job.

The WebGL prototype always renders its original knight immediately, then replaces only that piece after the new GLB arrives. A failed model fetch or missing Blender locally keeps the verified original in place. CI never silently skips the asset: Python source syntax, exact content hash, three-material geometry, 450 KB file budget, ear height/horse muzzle bounds, and live Chromium "loaded" status must pass. A deliberate GLB fetch failure must keep the diorama operational. The model is an incremental focal-art study, not a production Home redesign or a real GPU performance certification.
