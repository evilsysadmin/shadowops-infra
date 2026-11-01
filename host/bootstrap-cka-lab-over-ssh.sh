#!/usr/bin/env bash
# Operator workstation only. The OCI agent never receives installation authority.
set -euo pipefail

if [[ $# != 1 || ( "$1" != bootstrap && "$1" != inspect && "$1" != cluster-bootstrap && "$1" != cluster-verify ) ]]; then
  printf '%s\n' 'Usage: host/bootstrap-cka-lab-over-ssh.sh bootstrap|inspect|cluster-bootstrap|cluster-verify' >&2
  exit 64
fi
readonly action="$1"
readonly source_repo=https://github.com/evilsysadmin/shadowops-infra.git
readonly destination=ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org

for executable in ssh cloudflared; do
  command -v "$executable" >/dev/null 2>&1 || {
    printf 'CKA_LAB_OPERATOR_BLOCKED missing=%s\n' "$executable" >&2
    exit 69
  }
done
cloudflared --version >/dev/null || {
  printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED cloudflared-not-ready (select an installed version if using asdf)' >&2
  exit 69
}
ssh_options=(
  -o 'ProxyCommand=cloudflared access ssh --hostname %h'
  -o 'StrictHostKeyChecking=ask'
  -o 'ConnectTimeout=20'
  -o 'ServerAliveInterval=15'
)
if [[ -n "${CKA_OPERATOR_SSH_KEY:-}" ]]; then
  [[ -f "$CKA_OPERATOR_SSH_KEY" && ! -L "$CKA_OPERATOR_SSH_KEY" ]] || {
    printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED invalid-existing-key-path' >&2
    exit 65
  }
  ssh_options+=(-i "$CKA_OPERATOR_SSH_KEY")
fi

if [[ "$action" == inspect ]]; then
  # No Git fetch, checkout, installer, service start or repair on this path.
  ssh "${ssh_options[@]}" "$destination" \
    'sudo --non-interactive /usr/local/sbin/shadowops-cka-lab-staging inspect'
  exit 0
fi
if [[ "$action" == cluster-verify ]]; then
  # Read only: inspect the installed bounded runtime before checking the node.
  # The fixed root-owned script never repairs a missing cluster.
  ssh "${ssh_options[@]}" "$destination" \
    'sudo --non-interactive /usr/local/sbin/shadowops-cka-lab-staging inspect >/dev/null && sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I /opt/shadowops-infra/scripts/cka_lab_cluster.py verify-cluster'
  exit 0
fi

command -v git >/dev/null 2>&1 || {
  printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED missing=git' >&2
  exit 69
}
main_line="$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$source_repo" refs/heads/main)"
expected="${main_line%%$'\t'*}"
[[ "$main_line" == "$expected"$'\t'refs/heads/main && "$expected" =~ ^[a-f0-9]{40}$ ]] || {
  printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED invalid-protected-main' >&2
  exit 65
}
readonly expected
if [[ "$action" == cluster-bootstrap ]]; then
  printf 'Preparing private CKA cluster from protected main %s\n' "$expected"
else
  printf 'Installing CKA rootless runtime from protected main %s\n' "$expected"
fi

# Constant remote body; the only interpolated value is a validated SHA.
ssh "${ssh_options[@]}" "$destination" "sudo --non-interactive bash -se -- '$expected' '$action'" <<'REMOTE_BOOTSTRAP'
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $# == 2 && "$1" =~ ^[a-f0-9]{40}$ && ( "$2" == bootstrap || "$2" == cluster-bootstrap ) && "$(id -u)" == 0 ]] || exit 77
readonly expected="$1"
readonly action="$2"
readonly repo=/opt/shadowops-infra
readonly origin=https://github.com/evilsysadmin/shadowops-infra.git

# Root must not invoke Git or Python from a user-writable checkout.
python3 -I - <<'CHECK_OWNERSHIP'
import os
from pathlib import Path
import stat

def trusted(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))):
        raise SystemExit("CKA_LAB_OPERATOR_BLOCKED untrusted-checkout")

repo = Path("/opt/shadowops-infra")
for parent in repo.parents:
    trusted(parent, directory=True)
if repo.exists() or repo.is_symlink():
    trusted(repo, directory=True)
    metadata = repo / ".git"
    trusted(metadata, directory=True)
    count = 0
    def fail(error):
        raise error
    for current, dirs, files in os.walk(repo, followlinks=False, onerror=fail):
        for name in dirs + files:
            path = Path(current) / name
            trusted(path, directory=name in dirs)
            count += 1
            if count > 80000:
                raise SystemExit("CKA_LAB_OPERATOR_BLOCKED oversized-checkout")
CHECK_OWNERSHIP

if [[ -e "$repo" ]]; then
  [[ "$(git -c core.fsmonitor=false -C "$repo" remote get-url origin)" == "$origin" ]] || exit 65
  [[ -z "$(git -c core.fsmonitor=false -C "$repo" status --porcelain --untracked-files=normal)" ]] || {
    printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED checkout-has-local-changes' >&2
    exit 65
  }
  git -C "$repo" fetch --no-tags --depth=1 origin +refs/heads/main:refs/remotes/origin/main
else
  git clone --no-tags --depth=1 --branch main "$origin" "$repo"
fi
[[ "$(git -C "$repo" rev-parse refs/remotes/origin/main)" == "$expected" ]] || {
  printf '%s\n' 'CKA_LAB_OPERATOR_BLOCKED protected-main-changed-retry' >&2
  exit 65
}
git -c core.hooksPath=/dev/null -C "$repo" checkout --detach "$expected"
cd "$repo"
if [[ "$action" == bootstrap ]]; then
  python3 -I host/install-cka-lab-staging.py preflight "$expected"
  python3 -I host/install-cka-lab-staging.py install "$expected"
  /usr/local/sbin/shadowops-cka-lab-staging inspect
else
  # This proves the installed rootless daemon, private disk and cgroup limits.
  # A missing runtime or compromised policy blocks bootstrap before kind runs.
  /usr/local/sbin/shadowops-cka-lab-staging inspect >/dev/null
  sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I scripts/cka_lab_cluster.py install-tools
  sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I scripts/cka_lab_cluster.py bootstrap
  sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I scripts/cka_lab_cluster.py verify-cluster
fi
REMOTE_BOOTSTRAP

if [[ "$action" == cluster-bootstrap ]]; then
  printf '%s\n' 'CKA_LAB_OPERATOR_CLUSTER_BOOTSTRAP_COMPLETED labs_enabled=false'
else
  printf '%s\n' 'CKA_LAB_OPERATOR_BOOTSTRAP_COMPLETED labs_enabled=false'
fi
