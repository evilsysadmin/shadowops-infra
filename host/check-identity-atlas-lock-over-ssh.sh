#!/usr/bin/env bash
# Human-only, fixed root Atlas lock inspection and strictly guarded legacy fix.
# No deploy, no Docker commands, no change to Identity, DNS, backups or journal.
set -euo pipefail
[[ $# == 1 && ( "$1" == status || "$1" == repair ) ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=arguments'
  exit 64
}
readonly operation="$1"
for executable in git ssh cloudflared; do
  command -v "$executable" >/dev/null || {
    echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=missing-tool'
    exit 69
  }
done

repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
readonly origin='https://github.com/evilsysadmin/shadowops-infra.git'
case "$(git -C "$repo" remote get-url origin 2>/dev/null)" in
  "$origin"|'git@github.com:evilsysadmin/shadowops-infra.git'|'ssh://git@github.com/evilsysadmin/shadowops-infra.git') ;;
  *) echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=unexpected-origin'; exit 65 ;;
esac
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=dirty-checkout'
  exit 65
}
head="$(git -C "$repo" rev-parse HEAD)"
remote="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$origin" refs/heads/main)" || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=main-unavailable'
  exit 65
}
remote_sha="$(printf '%s\n' "$remote" | cut -f1)"
[[ "$head" =~ ^[a-f0-9]{40}$ && "$remote_sha" == "$head" ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=stale-main'
  exit 65
}

readonly host='ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org'
readonly operator='/usr/local/sbin/shadowops-identity-atlas-lock'
ssh_opts=(-o 'ProxyCommand=cloudflared access ssh --hostname %h' -o ConnectTimeout=20)

check() {
  local output
  if ! output="$(ssh "${ssh_opts[@]}" "$host" \
      "sudo --non-interactive $operator status" 2>/dev/null)"; then
    echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=status-unavailable'
    return 1
  fi
  local pattern='^IDENTITY_ATLAS_LOCK_STATUS state=(secure|legacy-0644|missing|unsafe)$'
  [[ "$output" =~ $pattern ]] || {
    echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=untrusted-receipt'
    return 1
  }
  printf '%s\n' "$output"
}

before="$(check)" || { printf '%s\n' "$before"; exit 1; }
if [[ "$operation" == status ]]; then
  printf '%s\n' "$before"
  exit 0
fi
[[ "$before" == 'IDENTITY_ATLAS_LOCK_STATUS state=legacy-0644' ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=not-exact-legacy'
  exit 1
}

# Require independent safe service and absence of durable rollback journal.
readonly inspect="$repo/host/inspect-identity-atlas-release-failure-over-ssh.sh"
readonly healthy='IDENTITY_ATLAS_HOST_DIAG operator=matched marker=trusted compose=trusted checkpoint=absent backup=fresh-metadata restore=matching-metadata container=atlas-healthy image_source=previous'
[[ -f "$inspect" && ! -L "$inspect" ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=missing-inspector'
  exit 1
}
if ! observed="$(bash "$inspect" 2>/dev/null)" || [[ "$observed" != "$healthy" ]]; then
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=unsafe-host-state'
  exit 1
fi

# The root operator repairs ONLY a singly linked, empty root:root 0644 lock
# under a private root-owned state dir, under exclusive flock. No unlink.
if ! result="$(ssh "${ssh_opts[@]}" "$host" \
      "sudo --non-interactive $operator repair" 2>/dev/null)"; then
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=repair-denied'
  exit 1
fi
[[ "$result" == 'IDENTITY_ATLAS_LOCK_REPAIR result=repaired-legacy-0644' ]] || {
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=untrusted-repair-receipt'
  exit 1
}

# Recheck both the exact lock and live service. Never claim success merely
# because chmod or the remote process exited successfully.
if ! after="$(check)" || [[ "$after" != 'IDENTITY_ATLAS_LOCK_STATUS state=secure' ]]; then
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=postrepair-lock-unverified'
  exit 1
fi
if ! observed="$(bash "$inspect" 2>/dev/null)" || [[ "$observed" != "$healthy" ]]; then
  echo 'IDENTITY_ATLAS_LOCK_SSH_BLOCKED reason=postrepair-host-unverified'
  exit 1
fi
echo 'IDENTITY_ATLAS_LOCK_SSH_REPAIRED lock=secure live_identity=unchanged checkpoint=absent'
