#!/usr/bin/env bash
# Human-operator-only, read-only Atlas takeover diagnosis via the existing Access SSH route.
# The remote receives a fixed, reviewed Python script on stdin; no installed
# wrapper, sudoers change, arbitrary commands, secrets or host writes.
set -euo pipefail

[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_MODE_BLOCKED reason=arguments'; exit 64; }
for executable in ssh cloudflared git; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_MODE_BLOCKED reason=missing-tool'
    exit 69
  }
done
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
origin='https://github.com/evilsysadmin/shadowops-infra.git'
[[ "$(git -C "$repo" remote get-url origin)" == "$origin" ]] || {
  echo 'IDENTITY_ATLAS_MODE_BLOCKED reason=unexpected-repo'
  exit 65
}
local_sha="$(git -C "$repo" rev-parse HEAD)"
remote_line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)"
remote_sha="${remote_line%%$'\t'*}"
[[ "$local_sha" =~ ^[a-f0-9]{40}$ && "$remote_sha" == "$local_sha" ]] || {
  echo 'IDENTITY_ATLAS_MODE_BLOCKED reason=outdated-checkout'
  exit 65
}
script="$repo/scripts/identity_staging_atlas_mode_operator.py"
[[ -f "$script" && ! -L "$script" ]] || {
  echo 'IDENTITY_ATLAS_MODE_BLOCKED reason=missing-script'
  exit 66
}
ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' -o ConnectTimeout=20 \
  ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org \
  'sudo --non-interactive python3 -I -' < "$script"
