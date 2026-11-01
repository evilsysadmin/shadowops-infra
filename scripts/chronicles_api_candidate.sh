#!/usr/bin/env bash
# Read-only candidate selection. Actual OCI image attestation and mutation are
# guarded separately; never treat a missing receipt as deployment authority.
set -euo pipefail
sha="${REQUESTED_SHA:-}"
if [[ -z "$sha" ]]; then
  sha="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
fi
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'CHRONICLES_API_ADMISSION_BLOCKED bad-sha' >&2; exit 64; }
if [[ "$TARGET_ENV" == 'production' && ! "$REQUESTED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'CHRONICLES_PRODUCTION_BLOCKED explicit-source-sha-required' >&2
  exit 64
fi
echo "sha=$sha" >> "$GITHUB_OUTPUT"
if [[ "$TARGET_ENV" == 'staging' && "$ONLY_IF_NEW" == 'true' ]]; then
  head="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
  if [[ "$sha" != "$head" ]]; then
    echo 'CHRONICLES_API_DISPATCH_SUPERSEDED'
    echo 'deploy_needed=false' >> "$GITHUB_OUTPUT"
    exit 0
  fi
fi
if [[ "$TARGET_ENV" == 'staging' ]]; then
  verdict="$(python3 scripts/chronicles_source_ci.py "$sha")"
  if [[ "$verdict" != 'ready' ]]; then
    if [[ "$GITHUB_EVENT_NAME" == 'workflow_dispatch' && "$ONLY_IF_NEW" != 'true' ]]; then
      echo 'Chronicles source CI is not fully green' >&2
      exit 1
    fi
    echo 'deploy_needed=false' >> "$GITHUB_OUTPUT"
    exit 0
  fi
fi
# Share the same exact-SHA, successful-run provenance check used
# by the Pages API gate. Merely counting artifacts is not a receipt.
if [[ "$TARGET_ENV" == 'staging' && ( "$GITHUB_EVENT_NAME" != 'workflow_dispatch' || "$ONLY_IF_NEW" == 'true' ) ]]; then
  if python3 scripts/chronicles_api_before_pages.py --receipt-only "$sha"; then
    echo 'deploy_needed=false' >> "$GITHUB_OUTPUT"
    exit 0
  else
    receipt_status=$?
    if (( receipt_status != 1 )); then
      echo 'CHRONICLES_API_RECEIPT_CHECK_INCONCLUSIVE' >&2
      exit "$receipt_status"
    fi
  fi
fi
echo 'deploy_needed=true' >> "$GITHUB_OUTPUT"
