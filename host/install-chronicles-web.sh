#!/usr/bin/env bash
# One-time, root-operated installation of the ShadowOps-owned Chronicles web
# staging wrapper on the EXISTING A1. Never run by a PR or OCI Run Command.
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'CHRONICLES_WEB_INSTALL_BLOCKED root-required' >&2
  exit 77
fi
if [[ $# -ne 1 || ! "$1" =~ ^[a-f0-9]{40}$ ]]; then
  echo 'CHRONICLES_WEB_INSTALL_BLOCKED expected-40-char-SHA' >&2
  exit 64
fi
readonly expected="$1"
readonly repo=/opt/shadowops-infra
[[ -d "$repo/.git" && ! -L "$repo" ]] || { echo 'CHRONICLES_WEB_INSTALL_BLOCKED trusted-checkout-missing' >&2; exit 66; }
for path in /opt "$repo" "$repo/.git" "$repo/host"; do
  [[ -d "$path" && ! -L "$path" && "$(stat -c %u "$path")" == 0 ]] || exit 66
  if (( 8#$(stat -c %a "$path") & 8#022 )); then
    echo 'CHRONICLES_WEB_INSTALL_BLOCKED source-directory-writable' >&2
    exit 66
  fi
done
actual="$(git -C "$repo" rev-parse HEAD)"
[[ "$actual" == "$expected" ]] || { echo 'CHRONICLES_WEB_INSTALL_BLOCKED wrong-source-sha' >&2; exit 65; }
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'CHRONICLES_WEB_INSTALL_BLOCKED modified-tracked-source' >&2; exit 65;
}
for file in host/chronicles-web-deploy.py host/chronicles-web.sudoers \
            scripts/shared_a1_host_guard.py compose.web.staging.yaml; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  if (( 8#$(stat -c %a "$source") & 8#022 )); then
    echo 'CHRONICLES_WEB_INSTALL_BLOCKED source-file-writable' >&2
    exit 66
  fi
done
visudo -cf "$repo/host/chronicles-web.sudoers" >/dev/null
readonly helper=/usr/local/sbin/shadowops-chronicles-web
readonly guards=/usr/local/lib/shadowops/shared_a1_host_guard.py
readonly composition=/etc/shadowops/chronicles-web-staging/compose.yaml
readonly sudoers=/etc/sudoers.d/102-shadowops-chronicles-web
for dest in "$helper" "$guards" "$composition" "$sudoers"; do
  [[ ! -L "$dest" ]] || { echo 'CHRONICLES_WEB_INSTALL_BLOCKED unsafe-target' >&2; exit 65; }
done
install -d -o root -g root -m 0755 /usr/local/lib/shadowops /etc/shadowops /etc/shadowops/chronicles-web-staging
install -d -o root -g root -m 0700 /var/lib/shadowops/chronicles-web-staging
install -o root -g root -m 0644 "$repo/scripts/shared_a1_host_guard.py" "$guards"
install -o root -g root -m 0644 "$repo/compose.web.staging.yaml" "$composition"
install -o root -g root -m 0755 "$repo/host/chronicles-web-deploy.py" "$helper"
# Only after installing the tested fixed-path wrapper and policy, authorize
# Oracle's nonprivileged agent to call that wrapper (never the Docker daemon).
install -o root -g root -m 0440 "$repo/host/chronicles-web.sudoers" "$sudoers"
visudo -cf "$sudoers" >/dev/null
printf '%s\\n' 'SHADOWOPS_CHRONICLES_WEB_HOST_WRAPPER_INSTALLED'
