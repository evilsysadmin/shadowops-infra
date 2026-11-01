#!/usr/bin/env bash
# Read-only candidate selection for the Chronicles Pages reconciler.
# Keep the exact source CI and verified live receipt gates in this order.
set -euo pipefail
sha="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || exit 64
echo "source_sha=$sha" >> "$GITHUB_OUTPUT"
# An automatic source dispatch is never allowed to deploy a newer
# revision accidentally, or re-publish an already verified SHA.
if [[ "$ONLY_IF_NEW" == 'true' && "$REQUESTED_SHA" != "$sha" ]]; then
  echo "CHRONICLES_PAGES_DISPATCH_SUPERSEDED requested=$REQUESTED_SHA"
  echo 'publish=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
# Fail closed: all three exact-SHA source workflows must finish green.
verdict="$(python3 scripts/chronicles_source_ci.py "$sha")"
if [[ "$verdict" != 'ready' ]]; then
  if [[ "$GITHUB_EVENT_NAME" == 'workflow_dispatch' ]]; then
    echo 'Chronicles source CI is not fully green' >&2
    exit 1
  fi
  echo 'publish=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
if [[ "$GITHUB_EVENT_NAME" != 'workflow_dispatch' || "$ONLY_IF_NEW" == 'true' ]]; then
  # A historical artifact alone is not proof that staging still
  # serves this SHA. Require a successful trusted run and live HTTPS.
  if python3 scripts/chronicles_pages_verified_receipt.py "$sha"; then
    echo 'publish=false' >> "$GITHUB_OUTPUT"
    exit 0
  else
    receipt_status=$?
    if (( receipt_status != 1 )); then
      echo "CHRONICLES_PAGES_RECEIPT_CHECK_INCONCLUSIVE" >&2
      exit "$receipt_status"
    fi
  fi
fi
echo 'publish=true' >> "$GITHUB_OUTPUT"
