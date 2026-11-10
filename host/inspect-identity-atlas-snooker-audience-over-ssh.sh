#!/usr/bin/env bash
# Authorized human, read-only Snooker audience custody diagnosis after rollback.
# Never reads/prints credentials; never writes host, Vault, Identity, Docker or DNS.
set -euo pipefail
[[ $# == 0 ]] || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=arguments'
  exit 64
}
for exe in git ssh cloudflared; do
  command -v "$exe" >/dev/null || {
    echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=dependency'
    exit 69
  }
done
repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
readonly origin='https://github.com/evilsysadmin/shadowops-infra.git'
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=origin'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=dirty-checkout'
  exit 65
}
head="$(git -C "$repo" rev-parse HEAD)"
remote="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)" || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=main-unavailable'
  exit 65
}
remote_sha="$(printf '%s\n' "$remote" | cut -f1)"
[[ "$head" =~ ^[a-f0-9]{40}$ && "$remote_sha" == "$head" ]] || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=stale-main'
  exit 65
}
readonly probe="$repo/scripts/identity_staging_atlas_snooker_audience_readonly.py"
[[ -f "$probe" && ! -L "$probe" ]] || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=missing-probe'
  exit 66
}

if ! report="$(ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' \
    -o ConnectTimeout=20 ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org \
    'sudo --non-interactive /opt/shadowops/oci-venv/bin/python -I -B -' < "$probe" 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=ssh-or-probe'
  exit 1
fi
safe='^IDENTITY_ATLAS_SNOOKER_AUDIENCE_DIAG source=(present|absent) atlas=(present|absent) consumer_parity=(matching|different) checkpoint=absent writes=false$'
[[ "$report" =~ $safe ]] || {
  echo 'IDENTITY_ATLAS_SNOOKER_AUDIENCE_SSH_BLOCKED reason=unrecognized-receipt'
  exit 1
}
printf '%s\n' "$report"
