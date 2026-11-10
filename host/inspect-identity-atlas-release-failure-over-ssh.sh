#!/usr/bin/env bash
# Human-only read-only triage following a blocked Atlas release over SSH.
# No deploy, docker write, sudoers modification, backup or rollback changes.
set -euo pipefail
[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=arguments'; exit 64; }
for tool in git ssh cloudflared; do
  command -v "$tool" >/dev/null || {
    echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=missing-tool'
    exit 69
  }
done
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly origin='https://github.com/evilsysadmin/shadowops-infra.git'
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=unexpected-repo'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=dirty-checkout'
  exit 65
}
local_sha="$(git -C "$repo" rev-parse HEAD)"
line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)" || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=main-unavailable'
  exit 65
}
[[ "$local_sha" =~ ^[a-f0-9]{40}$ && "${line%%$'\t'*}" == "$local_sha" ]] || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=stale-checkout'
  exit 65
}
readonly host=ssh-chess-studio-staging.shadowops.dpdns.org
readonly user=ubuntu
readonly probe="$repo/scripts/identity_staging_atlas_readonly_failure.py"
[[ -f "$probe" && ! -L "$probe" ]] || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=missing-probe'
  exit 66
}
# Explicitly separate connection from noninteractive sudo. Neither call
# changes host state, reads Docker environment nor prints SSH stderr.
ssh_opts=(-o 'ProxyCommand=cloudflared access ssh --hostname %h' -o ConnectTimeout=20)
if ! transport="$(ssh "${ssh_opts[@]}" "$user@$host" 'printf IDENTITY_ATLAS_SSH_TRANSPORT_OK' 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=ssh-transport'
  exit 1
fi
[[ "$transport" == IDENTITY_ATLAS_SSH_TRANSPORT_OK ]] || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=ssh-transport'
  exit 1
}
if ! report="$(ssh "${ssh_opts[@]}" "$user@$host" \
  'sudo --non-interactive python3 -I -' < "$probe" 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=sudo-or-readonly-probe'
  exit 1
fi
# Whitelist every categorical result. Never relay unrecognized host output.
pattern='^IDENTITY_ATLAS_HOST_DIAG operator=(matched|untrusted|mismatch) marker=(trusted|missing|unsafe) compose=(trusted|missing|unsafe) checkpoint=(absent|present|unsafe) backup=(fresh-metadata|unverified) restore=(matching-metadata|unverified) container=(atlas-healthy|unhealthy|not-atlas|ambiguous|unverified|untrusted-image) image_source=(previous|candidate|other|unverified)$'
[[ "$report" =~ $pattern ]] || {
  echo 'IDENTITY_ATLAS_HOST_DIAG_BLOCKED reason=unexpected-readonly-receipt'
  exit 1
}
printf '%s\n' "$report"
