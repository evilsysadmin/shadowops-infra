#!/usr/bin/env bash
# Called from chronicles-source/frontend, after npm ci and npm run build.
# Keep common static build contracts identical across staging and production.
set -euo pipefail
if [[ "${1:-}" != staging && "${1:-}" != production ]]; then
  echo 'CHRONICLES_ARTIFACTS_INVALID_TARGET expected staging or production' >&2
  exit 64
fi
target="$1"
# The in-app update banner must read the exact release being deployed.
test -s dist/release.json
node -e "const fs=require('node:fs');const m=JSON.parse(fs.readFileSync('dist/release.json','utf8'));if(m.build!==process.env.VITE_BUILD_SHA) process.exit(1)"
grep -q 'Chronicles of Matthias' dist/index.html
grep -q '/assets/' dist/index.html
# The real game, not a shell: original component, Tactics, the
# Three.js renderer and server-side runs must be in the bundle.
ls dist/assets/ChroniclesOfMatthias-*.js
ls dist/assets/ChroniclesOfMatthiasTactics-*.js
ls dist/assets/chroniclesOfMatthiasThree-*.js
# Runtime assets served from public/ (not the SPA fallback).
test -s dist/audio/orchestra/violin-fs3.mp3
test -s dist/models/matthias-home-canonical.glb
grep -lFq '/chronicles/runs' dist/assets/*.js
if [[ "$target" == staging ]]; then
  grep -lFq 'chronicles-api-staging.shadowops.dpdns.org' dist/assets/*.js
else
  grep -lFq 'chronicles-api.shadowops.dpdns.org/api' dist/assets/*.js
  if grep -lFq 'chronicles-api-staging.' dist/assets/*.js; then echo 'staging API in production build' >&2; exit 1; fi
fi
