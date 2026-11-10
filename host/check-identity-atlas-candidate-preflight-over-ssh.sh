#!/usr/bin/env bash
# Explicit human-only staging candidate PRE-FLIGHT. This is NOT the Atlas release.
# It may pull the exact pinned image and create/remove a disposable Docker network
# and read-only preflight container. It never recreates the live Identity service,
# changes the Atlas marker, deploys Compose, modifies Pages/DNS, or performs a backup.
set -euo pipefail
[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=arguments'; exit 64; }

readonly source_sha=4a48dff49c4a77703c6f4b164120d3cef8e77e76
readonly digest=sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91
readonly origin=https://github.com/evilsysadmin/shadowops-infra.git
readonly ssh_host=ssh-chess-studio-staging.shadowops.dpdns.org
readonly operator=/usr/local/sbin/shadowops-identity-atlas-preflight

for executable in git ssh cloudflared bash; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=missing-tool'
    exit 69
  }
done
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=origin'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=dirty-checkout'
  exit 65
}
head="$(git -C "$repo" rev-parse HEAD)"
line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)" || {
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=main-unavailable'
  exit 65
}
[[ "$head" =~ ^[a-f0-9]{40}$ && "${line%%$'\t'*}" == "$head" ]] || {
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=stale-main'
  exit 65
}

# The already reviewed root-only inspector must prove the exact same old,
# healthy Atlas Identity and ABSENT durable transition journal. No 'force' path.
readonly inspect="$repo/host/inspect-identity-atlas-release-failure-over-ssh.sh"
readonly stable='IDENTITY_ATLAS_HOST_DIAG operator=matched marker=trusted compose=trusted checkpoint=absent backup=fresh-metadata restore=matching-metadata container=atlas-healthy image_source=previous'
[[ -f "$inspect" && ! -L "$inspect" ]] || {
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=missing-inspector'
  exit 66
}
if ! before="$(bash "$inspect" 2>/dev/null)" || [[ "$before" != "$stable" ]]; then
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=unsafe-preflight-state'
  exit 1
fi

# Fixed sudo delegated operator: NOT the deployment wrapper. Operator holds
# the common deploy.lock, verifies trusted Atlas paths and its image labels,
# and cleans up its isolated network even if the candidate preflight fails.
# Capture stderr locally and never forward arbitrary Docker/SSH output.
ssh_opts=(-o 'ProxyCommand=cloudflared access ssh --hostname %h' -o ConnectTimeout=20)
succeeded=false
if receipt="$(ssh "${ssh_opts[@]}" "ubuntu@$ssh_host" \
  "sudo --non-interactive $operator preflight $digest $source_sha" 2>&1)"; then
  succeeded=true
fi
readonly expected="IDENTITY_ATLAS_PREFLIGHT_OK source_sha=$source_sha digest=$digest"
failure='unknown'
if [[ "$succeeded" != true && "$receipt" =~ ^IDENTITY_ATLAS_PREFLIGHT_BLOCKED[[:space:]]type=([A-Za-z][A-Za-z0-9]{0,48})$ ]]; then
  failure="${BASH_REMATCH[1]}"
fi

# Independently prove live Identity still matches its old image after this
# isolated check, whether it passed or failed. Fail closed on any uncertainty.
if ! after="$(bash "$inspect" 2>/dev/null)" || [[ "$after" != "$stable" ]]; then
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=postflight-state-unverified'
  exit 1
fi
if [[ "$succeeded" == true && "$receipt" == "$expected" ]]; then
  printf '%s\n' 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_OK live_identity=unchanged rollback_checkpoint=absent'
  exit 0
fi
if [[ "$succeeded" == true ]]; then
  echo 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=unexpected-receipt'
else
  printf 'IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_BLOCKED reason=operator-or-ssh type=%s\n' "$failure"
fi
exit 1
