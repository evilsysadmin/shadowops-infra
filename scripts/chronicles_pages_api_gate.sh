#!/usr/bin/env bash
# Pages must not publish until the matching API generation is admitted.
# This is the original read-only api-ready job gate, not an independent deployer.
set -euo pipefail
if python3 scripts/chronicles_api_before_pages.py "$ADMITTED_SHA"; then
  # The API can become ready after a newer Infra main supersedes
  # this workflow. Do not launch the Pages mutation job in that case.
  owner_main="$(gh api repos/evilsysadmin/shadowops-infra/commits/main --jq .sha)"
  [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$owner_main" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'CHRONICLES_PAGES_INVALID_INFRA_SHA' >&2
    exit 64
  }
  if [[ "$owner_main" != "$GITHUB_SHA" ]]; then
    echo "CHRONICLES_PAGES_INFRA_SUPERSEDED_BEFORE_RELEASE current=$owner_main"
    echo '::notice title=Chronicles Pages superseded::Infra main advanced; the old owner workflow will not publish.'
    echo 'publish=false' >> "$GITHUB_OUTPUT"
    exit 0
  fi
  # The API receipt can arrive just as source main advances. A
  # successful historical API deploy must never launch a now-stale
  # Pages release and trip the owner gate as a false-red failure.
  source_main="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
  [[ "$ADMITTED_SHA" =~ ^[0-9a-f]{40}$ && "$source_main" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'CHRONICLES_PAGES_INVALID_SOURCE_SHA' >&2
    exit 64
  }
  if [[ "$source_main" != "$ADMITTED_SHA" ]]; then
    echo "CHRONICLES_PAGES_SOURCE_SUPERSEDED_AFTER_API admitted=$ADMITTED_SHA current=$source_main"
    echo '::notice title=Chronicles Pages superseded::Source main advanced after API verification; the obsolete client will not publish.'
    echo 'publish=false' >> "$GITHUB_OUTPUT"
    exit 0
  fi
  echo 'publish=true' >> "$GITHUB_OUTPUT"
  exit 0
fi
current="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
if [[ "$current" != "$ADMITTED_SHA" ]]; then
  echo "CHRONICLES_PAGES_SUPERSEDED_BEFORE_RELEASE sha=$ADMITTED_SHA"
  echo 'publish=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
echo 'API gate failed for current SHA; no Pages mutation' >&2
exit 1
