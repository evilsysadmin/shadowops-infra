#!/usr/bin/env bash
# Human-only, NO state-changing actions: why did the exact Atlas release block?
set -euo pipefail
[[ $# == 0 ]] || { echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=arguments'; exit 64; }
for executable in ssh git cloudflared; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=missing-tool'
    exit 69
  }
done

repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
readonly origin='https://github.com/evilsysadmin/shadowops-infra.git'
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=origin'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=dirty-checkout'
  exit 65
}
head="$(git -C "$repo" rev-parse HEAD)"
remote_sha="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main | cut -f1)" || {
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=main-unavailable'
  exit 65
}
[[ "$head" =~ ^[a-f0-9]{40}$ && "$remote_sha" == "$head" ]] || {
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=stale-main'
  exit 65
}

probe="$repo/scripts/identity_staging_atlas_release_gate_audit.py"
[[ -f "$probe" && ! -L "$probe" ]] || {
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=missing-probe'
  exit 66
}
# Same OCI venv as the installed root release operator, without invoking it.
# It reads metadata/backup evidence and invokes Docker inventory and Compose
# 'config' only. No backup operation, image pull, preflight container or cutover.
if ! result="$(ssh -o 'ProxyCommand=cloudflared access ssh --hostname %h' \
  -o ConnectTimeout=20 ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org \
  'sudo --non-interactive /opt/shadowops/oci-venv/bin/python -I -' < "$probe" 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=ssh-or-venv'
  exit 1
fi
blocked='^IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=(authority|checkpoint|trusted-paths|atlas-marker|backup-restore-crypto|shared-host|live-container|public-source|compose-previous|compose-candidate|candidate-cache)$'
passed='^IDENTITY_ATLAS_RELEASE_GATES_OK preactivation=verified cached_candidate=(matched|not-cached) candidate_preflight=not-run transition=not-attempted$'
if [[ "$result" =~ $blocked || "$result" =~ $passed ]]; then
  printf '%s\n' "$result"
else
  echo 'IDENTITY_ATLAS_RELEASE_GATE_BLOCKED stage=unrecognized-receipt'
  exit 1
fi
