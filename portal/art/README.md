# First modeled GLB asset — celestial armillary

Source and copyright: original ShadowOps parametric artwork created in this repository. No third-party geometry, textures, or image copyrights. Source-of-truth: \`build-armillary.mjs\`; generated .glb is disposable.

Generate: \`npm run art:build\` inside \`portal/\`. A pinned Three.js version and deterministic vertex/material ordering produce the same content-addressed asset. The HTML/app does not reference a stale stable-name binary: the generated JS exports the exact SHA-derived pathname.

Acceptance: \`npm test\` parses the GLB 2.0 header and source hash; browser CI must actually fetch/parse it on desktop and skip mobile. The world navigations must survive any GLB load failure. Three merged primitives keep draw calls bounded. This pilot validates authoring/distribution, **not** production-grade artistic quality. Later production GLBs should be authored and revised in DCC software and served from R2 with explicit provenance and licenses.
