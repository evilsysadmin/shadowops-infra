#!/usr/bin/env bash
# One-time operator bootstrap via the EXISTING Cloudflare SSH tunnel.
# Runs from the operator's own Linux machine. Never inside CI or OCI agent.
set -euo pipefail

readonly source_repo='https://github.com/evilsysadmin/shadowops-infra.git'
readonly destination='ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org'

# Optional argument: an exact protected main SHA to pin. Without it, the
# script installs the CURRENT protected main (resolved below and re-verified
# on the host), so the operator never has to copy a hash.
if [[ $# -gt 1 || ( $# -eq 1 && ! "$1" =~ ^[0-9a-f]{40}$ ) ]]; then
  printf '%s\n' 'Usage: host/bootstrap-chronicles-api-over-ssh.sh [exact-protected-main-SHA]' >&2
  exit 64
fi

for executable in ssh cloudflared git; do
  command -v "$executable" >/dev/null 2>&1 || {
    printf 'CHRONICLES_API_BOOTSTRAP_BLOCKED missing=%s\n' "$executable" >&2
    exit 69
  }
done

# Don't install an unreviewed branch, tag, stale parent or arbitrary SHA.
# Recheck on the host too: main can change between these two observations.
main_line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$source_repo" refs/heads/main)"
main_sha="${main_line%%$'\t'*}"
expected="${1:-$main_sha}"
readonly expected
printf 'Installing protected main %s\n' "$expected"
if [[ ! "$main_sha" =~ ^[0-9a-f]{40}$ || "$main_sha" != "$expected" ]]; then
  printf '%s\n' 'CHRONICLES_API_BOOTSTRAP_BLOCKED source-main-sha-mismatch' >&2
  exit 65
fi

ssh_options=(
  -o 'ProxyCommand=cloudflared access ssh --hostname %h'
  -o 'ConnectTimeout=20'
  -o 'ServerAliveInterval=15'
)
# Optional existing private key on the operator's computer. Never transfer it
# to the server or GitHub. Otherwise use normal local SSH agent/key discovery.
if [[ -n "${CHRONICLES_OPERATOR_SSH_KEY:-}" ]]; then
  [[ -f "$CHRONICLES_OPERATOR_SSH_KEY" && ! -L "$CHRONICLES_OPERATOR_SSH_KEY" ]] || {
    printf '%s\n' 'CHRONICLES_API_BOOTSTRAP_BLOCKED ssh-key-path-invalid' >&2
    exit 65
  }
  ssh_options+=(-i "$CHRONICLES_OPERATOR_SSH_KEY")
fi

printf '%s\n' 'Connecting through the existing operator SSH tunnel (no direct A1 port 22).'
# The remote script is a constant stdin body. The only argument is a SHA
# prevalidated against current protected main. Do not disable SSH host-key
# verification or interpolate shell input into the script body.
ssh "${ssh_options[@]}" "$destination" "sudo --non-interactive bash -se -- '$expected'" <<'REMOTE_BOOTSTRAP'
set -euo pipefail
[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || exit 64
readonly expected="$1"
readonly repo=/opt/shadowops-infra
readonly origin=https://github.com/evilsysadmin/shadowops-infra.git

# The existing 'ubuntu' SSH identity must already have operator sudo rights.
# Oracle's unprivileged 'ocarun' never obtains sudo or Docker group access.
[[ "$(id -u)" == 0 ]] || exit 77
command -v git >/dev/null 2>&1 || exit 69
command -v visudo >/dev/null 2>&1 || exit 69
if [[ -e "$repo" || -L "$repo" ]]; then
  [[ -d "$repo/.git" && ! -L "$repo" ]] || exit 66
  [[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || exit 65
  [[ "$(git -C "$repo" remote get-url origin)" == "$origin" ]] || exit 65
  git -C "$repo" fetch --no-tags --depth=1 origin +refs/heads/main:refs/remotes/origin/main
else
  git clone --no-tags --depth=1 --branch main "$origin" "$repo"
fi
remote_main="$(git -C "$repo" rev-parse refs/remotes/origin/main)"
if [[ "$remote_main" != "$expected" ]]; then
  printf '%s\n' 'CHRONICLES_API_BOOTSTRAP_BLOCKED remote-main-changed' >&2
  exit 65
fi
git -C "$repo" checkout --detach "$expected"
exec "$repo/host/install-chronicles-api.sh" "$expected"
REMOTE_BOOTSTRAP

printf '%s\n' 'CHRONICLES_API_OPERATOR_BOOTSTRAP_COMPLETED'
printf '%s\n' 'This installs only the restricted API wrapper. No container has been started.'
