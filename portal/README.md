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
