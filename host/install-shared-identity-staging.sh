#!/usr/bin/env bash
# Operator-only installation of the two reviewed staging Identity mechanisms.
# Does not start/restart services, alter runtime secrets or enable consumer flags.
set -euo pipefail
[[ "${EUID:-$(id -u)}" == 0 && $# == 1 && "$1" =~ ^[a-f0-9]{40}$ ]] || exit 77
readonly repo=/opt/shadowops-infra
readonly expected="$1"
# This verifies source ownership, current SHA, clean checkout and fixed paths.
bash "$repo/host/install-identity-staging.sh" "$expected"
for file in host/chronicles-api-deploy.py scripts/shared_a1_host_guard.py; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  (( (8#$(stat -c %a "$source") & 8#022) == 0 )) || exit 66
done
[[ ! -L /usr/local/sbin/shadowops-chronicles-api ]] || exit 66
# Same fixed Chronicles wrapper; production opt-in remains explicitly rejected.
# Its Compose policies, runtime env files and running containers are untouched.
install -o root -g root -m 0755 "$repo/host/chronicles-api-deploy.py" /usr/local/sbin/shadowops-chronicles-api
printf '%s\n' SHADOWOPS_SHARED_IDENTITY_STAGING_WRAPPERS_INSTALLED
