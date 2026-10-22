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

The world-focus change now pans the camera only subtly and respects reduced-motion immediately. The renderer runs at **up to** 45fps desktop/30fps mobile and halts its rAF chain on a hidden tab; on visibility restoration it repaints and resumes. Frame scheduling does not confuse rAF timestamps with a force flag. The WebGL screen remains optional and root DNS ownership is unchanged.

## First authored GLB object / build-time pipeline

`art/build-armillary.mjs` is the source master of a small celestial armillary instrument. It exports a fully indexed GLB 2.0 with three merged PBR primitives and a SHA-256 content-addressed filename. The artifact is generated by `npm run art:build` (automatically before `dev`, `build` and unit tests), never committed as a binary: `public/art/armillary-*.glb` and `src/armillaryAsset.generated.mjs` are outputs. Desktop loads the model lazily with Three.js GLTFLoader, while mobile and no-WebGL skip it; a failed optional asset must never block the game catalog. The authored geometry is **a first pipeline pilot**, not final approved cinematic GLB environment art. Larger production assets will live in an independent CDN/R2 manifest with provenance and measured GPU cost.

## Three world-specific authored GLB reliefs

The art source in `art/build-relics.mjs` adds three different sculptural emblems (`relic-chess`, `relic-chronicles`, `relic-star`). Each has original geometry, its own three PBR primitives, an independently SHA-256 addressed GLB asset and a per-file size/triangle gate. The browser imports these only on desktop after the scene becomes interactive; mobile does not download them. The generated JS manifest is deliberately gitignored. These are restrained architectural details — **not** the final AAA-quality authored gallery, which remains gated on #153.

## Authored architectural GLB pilot

`art/build-gallery-frame.mjs` now authors one SHA-256-named GLB for the common three-bay façade (arches, dressed stone keys, shafts and cornice). The runtime no longer builds those procedural meshes on the successful path; instead it asynchronously loads a three-primitive PBR sculpture. If the GLB fails, the preceding procedural construction is retained as a fallback. Unit tests validate the binary and size, and Playwright exercises both real loading and the deliberate network-failure recovery. This remains a parametric source-authored intermediate—not a signed-off Blender environment or final CDN rollout; #153 still tracks those acceptance gates.
