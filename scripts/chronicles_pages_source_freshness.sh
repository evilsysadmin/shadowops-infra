#!/usr/bin/env bash
# Two independent exact-source gates: before Pages mutations and after smoke.
# The just-in-time source recheck inside the wrangler publish step remains intact.
set -euo pipefail
phase="${1:-}"
case "$phase" in
  before-publish|after-smoke) ;;
  *) echo 'CHRONICLES_PAGES_INVALID_FRESHNESS_PHASE' >&2; exit 64 ;;
esac
[[ "$ADMITTED_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'CHRONICLES_PAGES_INVALID_ADMITTED_SHA' >&2
  exit 64
}
current="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
[[ "$current" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'CHRONICLES_PAGES_INVALID_CURRENT_MAIN_SHA' >&2
  exit 65
}
if [[ "$current" != "$ADMITTED_SHA" ]]; then
  if [[ "$phase" == before-publish ]]; then
    echo "CHRONICLES_PAGES_SUPERSEDED_BEFORE_PUBLISH sha=$ADMITTED_SHA current=$current"
    echo '::notice title=Chronicles Pages superseded::Source main advanced; no staging publish or receipt.'
    printf '**State: superseded before Pages mutations.** The obsolete build was not published and no receipt was issued.\n' >> "$GITHUB_STEP_SUMMARY"
  else
    echo "CHRONICLES_PAGES_SUPERSEDED_AFTER_SMOKE sha=$ADMITTED_SHA current=$current"
    echo "::notice title=Chronicles Pages superseded::Public browser checks passed, but source main advanced. No staging receipt will be written."
    printf '**State: superseded after public smoke.** This run validated an older source revision but cannot certify the current staging generation. No receipt issued.\\n' >> "$GITHUB_STEP_SUMMARY"
  fi
  echo 'fresh=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
echo 'fresh=true' >> "$GITHUB_OUTPUT"
