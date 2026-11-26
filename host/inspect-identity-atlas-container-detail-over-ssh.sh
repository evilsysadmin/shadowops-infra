#!/usr/bin/env bash
# Human-only, read-only classification of the active Identity mount/networks.
set -euo pipefail
[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=arguments'; exit 64; }
for executable in ssh cloudflared git; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=missing-tool'
    exit 69
  }
done
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly origin='https://github.com/evilsysadmin/shadowops-infra.git'
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=unexpected-repo'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=dirty-checkout'
  exit 65
}
local_sha="$(git -C "$repo" rev-parse HEAD)"
remote_sha="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main | cut -f1)" || {
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=main-unavailable'
  exit 65
}
[[ "$local_sha" =~ ^[a-f0-9]{40}$ && "$remote_sha" == "$local_sha" ]] || {
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=stale-main'
  exit 65
}
script="$repo/scripts/identity_staging_atlas_container_detail.py"
[[ -f "$script" && ! -L "$script" ]] || {
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=missing-probe'
  exit 66
}
if ! report="$(ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' \
  -o ConnectTimeout=20 ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org \
  'sudo --non-interactive python3 -I -' < "$script" 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=ssh-or-readonly-probe'
  exit 1
fi
pattern='^IDENTITY_ATLAS_CONTAINER_DETAIL count=(single|missing|ambiguous) mount=(atlas|local|snooker|staradvs|other|missing|ambiguous|unsafe) networks=(atlas|local|other|missing|ambiguous) state=(running|exited|created|restarting|paused|dead|unknown)$'
[[ "$report" =~ $pattern ]] || {
  echo 'IDENTITY_ATLAS_CONTAINER_DETAIL_BLOCKED reason=unrecognized-receipt'
  exit 1
}
printf '%s\n' "$report"
