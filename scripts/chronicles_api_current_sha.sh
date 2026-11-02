#!/usr/bin/env bash
# Read-only, fail-closed source SHA validation for both OCI staging gates.
# Emit only the validated current source SHA; the two independent gates
# retain their own supersession and receipt/admission decisions.
set -euo pipefail
admitted="${1:-}"
[[ "$admitted" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'CHRONICLES_OCI_INVALID_SOURCE' >&2
  exit 64
}
current="$(gh api repos/evilsysadmin/chronicles-of-matthias/commits/main --jq .sha)"
[[ "$current" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'CHRONICLES_OCI_INVALID_MAIN_SHA' >&2
  exit 65
}
printf '%s\n' "$current"
