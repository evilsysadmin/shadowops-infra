#!/usr/bin/env bash
# Explicit authorized-human fallback when OCI Run Command has NOT created a release.
# Root operator still enforces Atlas backup/restore, live source, Snooker audience
# and verified rollback. This script never edits the Atlas takeover marker,
# credentials, compose policy, tunnel, Cloudflare Pages or DNS.
set -euo pipefail
[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=arguments' >&2; exit 64; }

readonly source_sha=4a48dff49c4a77703c6f4b164120d3cef8e77e76
readonly digest=sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91
readonly repo=https://github.com/evilsysadmin/shadowops-infra.git
readonly ssh_host=ssh-chess-studio-staging.shadowops.dpdns.org
readonly wrapper=/usr/local/sbin/shadowops-identity-atlas-deploy
readonly expected="IDENTITY_ATLAS_DEPLOY_OK source_sha=$source_sha digest=$digest"
readonly expected_public="SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present release_sha=$source_sha"

for executable in git ssh cloudflared python3; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=missing-dependency' >&2
    exit 69
  }
done

cd "$(dirname "$0")/.."
[[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "$(pwd -P)" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=checkout' >&2
  exit 65
}
case "$(git remote get-url origin 2>/dev/null)" in
  "$repo"|git@github.com:evilsysadmin/shadowops-infra.git) ;;
  *) echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=origin' >&2; exit 65 ;;
esac
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=dirty-checkout' >&2
  exit 65
}
readonly head="$(git rev-parse HEAD)"
[[ "$head" =~ ^[a-f0-9]{40}$ ]] || exit 65
remote="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$repo" refs/heads/main)" || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=main-unavailable' >&2
  exit 65
}
[[ "${remote%%$'\t'*}" == "$head" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=stale-main' >&2
  exit 65
}

# The image and OCI digest were admitted on the previously protected
# staging workflow 42823811617. The independent read-only OCI command
# creation inventory 42821843479 (new attempt) found no remote command,
# and public Identity stayed on the old SHA. A human deliberately invokes
# the same exact root-owned operator via the established Cloudflare SSH path.
# Do NOT blindly repeat this operation if the wrapper reports a failure.
if ! receipt="$(ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' \
    -o ConnectTimeout=20 "ubuntu@$ssh_host" \
    "sudo --non-interactive $wrapper deploy $digest $source_sha" 2>&1)"; then
  # A failed authorized operator can emit ONE fixed, sanitized stage/rollback
  # marker. Only that exact shape is allowed through this SSH boundary.
  # Cloudflare Access banners, sudo messages, Docker output and credentials
  # are all discarded; no generic verbose SSH mode or raw stderr forwarding.
  safe='^IDENTITY_ATLAS_DEPLOY_BLOCKED type=[A-Za-z][A-Za-z0-9]{0,48} stage=(request|lock|candidate-identity|trusted-paths|atlas-marker|backup-restore|shared-host|live-container|public-source|candidate-preflight|compose-previous|compose-candidate|transition-start|candidate-activation|candidate-inspect|candidate-public|candidate-audience|rollback-activation|rollback-inspect|rollback-public|complete) rollback=(not-started|attempted|verified|unverified)
[[ "$receipt" == "$expected" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=unexpected-host-receipt' >&2
  exit 1
}
printf '%s\n' "$expected"

# A success from root is not final browser acceptance. Check the same external
# HTTPS issuer endpoint that the Pages publisher will rely on.
public="$(python3 scripts/snooker_identity_public_probe.py 2>/dev/null)" || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=public-probe' >&2
  exit 1
}
[[ "$public" == "$expected_public" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=public-not-accepted' >&2
  exit 1
}
printf '%s\n' 'IDENTITY_ATLAS_SSH_PUBLIC_SNOOKER_READY'

  if [[ "$receipt" =~ $safe ]]; then
    printf '%s\n' "$receipt" >&2
  else
    echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=host-or-operator' >&2
  fi
  exit 1
fi
[[ "$receipt" == "$expected" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=unexpected-host-receipt' >&2
  exit 1
}
printf '%s\n' "$expected"

# A success from root is not final browser acceptance. Check the same external
# HTTPS issuer endpoint that the Pages publisher will rely on.
public="$(python3 scripts/snooker_identity_public_probe.py 2>/dev/null)" || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=public-probe' >&2
  exit 1
}
[[ "$public" == "$expected_public" ]] || {
  echo 'IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=public-not-accepted' >&2
  exit 1
}
printf '%s\n' 'IDENTITY_ATLAS_SSH_PUBLIC_SNOOKER_READY'
