#!/usr/bin/env bash
# Install the reviewed fixed Identity wrapper through the existing operator SSH tunnel.
# This installs policy only. It does not start containers or switch a product login.
set -euo pipefail
[[ $# == 0 ]] || exit 64
readonly origin=https://github.com/evilsysadmin/shadowops-infra.git
for executable in ssh cloudflared git; do command -v "$executable" >/dev/null || { printf 'IDENTITY_STAGING_BOOTSTRAP_BLOCKED missing=%s\n' "$executable" >&2; exit 69; }; done
main_line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)"
expected="${main_line%%$'\t'*}"
[[ "$expected" =~ ^[a-f0-9]{40}$ ]] || exit 65
ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' -o ConnectTimeout=20 \
  ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org "sudo --non-interactive bash -se -- '$expected'" <<'REMOTE'
set -euo pipefail
[[ $# == 1 && "$1" =~ ^[a-f0-9]{40}$ && "$(id -u)" == 0 ]] || exit 77
readonly expected="$1"
readonly repo=/opt/shadowops-infra
readonly origin=https://github.com/evilsysadmin/shadowops-infra.git
if [[ -e "$repo" || -L "$repo" ]]; then
  [[ -d "$repo/.git" && ! -L "$repo" && "$(git -C "$repo" remote get-url origin)" == "$origin" ]] || exit 66
  [[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || exit 65
  git -C "$repo" fetch --no-tags --depth=1 origin +refs/heads/main:refs/remotes/origin/main
else
  git clone --no-tags --depth=1 --branch main "$origin" "$repo"
fi
[[ "$(git -C "$repo" rev-parse origin/main)" == "$expected" ]] || exit 65
git -C "$repo" checkout --detach "$expected"
exec "$repo/host/install-identity-staging.sh" "$expected"
REMOTE
