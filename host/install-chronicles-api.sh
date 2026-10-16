#!/usr/bin/env bash
# One-time, root-operated installation of the ShadowOps-owned Chronicles API
# staging wrapper on the EXISTING A1. Never run by a PR or OCI Run Command.
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'CHRONICLES_API_INSTALL_BLOCKED root-required' >&2; exit 77
fi
if [[ $# -ne 1 || ! "$1" =~ ^[a-f0-9]{40}$ ]]; then
  echo 'CHRONICLES_API_INSTALL_BLOCKED expected-40-char-SHA' >&2; exit 64
fi
readonly expected="$1"
readonly repo=/opt/shadowops-infra
readonly oci_sdk='oci==2.185.2'
[[ -d "$repo/.git" && ! -L "$repo" ]] || { echo 'CHRONICLES_API_INSTALL_BLOCKED trusted-checkout-missing' >&2; exit 66; }
for path in /opt "$repo" "$repo/.git" "$repo/host"; do
  [[ -d "$path" && ! -L "$path" && "$(stat -c %u "$path")" == 0 ]] || exit 66
  if (( 8#$(stat -c %a "$path") & 8#022 )); then
    echo 'CHRONICLES_API_INSTALL_BLOCKED source-directory-writable' >&2; exit 66
  fi
done
[[ "$(git -C "$repo" rev-parse HEAD)" == "$expected" ]] || { echo 'CHRONICLES_API_INSTALL_BLOCKED wrong-source-sha' >&2; exit 65; }
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || {
  echo 'CHRONICLES_API_INSTALL_BLOCKED modified-tracked-source' >&2; exit 65; }
for file in host/chronicles-api-deploy.py host/chronicles-api.sudoers \
            scripts/shared_a1_host_guard.py compose.api.staging.yaml; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  if (( 8#$(stat -c %a "$source") & 8#022 )); then
    echo 'CHRONICLES_API_INSTALL_BLOCKED source-file-writable' >&2; exit 66
  fi
done
visudo -cf "$repo/host/chronicles-api.sudoers" >/dev/null
readonly helper=/usr/local/sbin/shadowops-chronicles-api
readonly guards=/usr/local/lib/shadowops/shared_a1_host_guard.py
readonly composition=/etc/shadowops/chronicles-api-staging/compose.yaml
readonly sudoers=/etc/sudoers.d/103-shadowops-chronicles-api
readonly venv=/opt/shadowops/oci-venv
for dest in "$helper" "$guards" "$composition" "$sudoers" "$venv"; do
  [[ ! -L "$dest" ]] || { echo 'CHRONICLES_API_INSTALL_BLOCKED unsafe-target' >&2; exit 65; }
done
install -d -o root -g root -m 0755 /usr/local/lib/shadowops /etc/shadowops /opt/shadowops
# The runtime directory holds the Vault-derived env files: root only.
install -d -o root -g root -m 0700 /etc/shadowops/chronicles-api-staging /var/lib/shadowops/chronicles-api-staging
# Root-owned OCI SDK used only to read the Chronicles bundle by Instance Principal.
if [[ ! -x "$venv/bin/python" ]]; then
  python3 -m venv "$venv"
fi
"$venv/bin/pip" install --disable-pip-version-check --quiet "$oci_sdk"
chown -R root:root "$venv"; chmod -R go-w "$venv"
install -o root -g root -m 0644 "$repo/scripts/shared_a1_host_guard.py" "$guards"
install -o root -g root -m 0644 "$repo/compose.api.staging.yaml" "$composition"
install -o root -g root -m 0755 "$repo/host/chronicles-api-deploy.py" "$helper"
# Only after the tested wrapper and policy exist, authorize Oracle's agent.
install -o root -g root -m 0440 "$repo/host/chronicles-api.sudoers" "$sudoers"
visudo -cf "$sudoers" >/dev/null
printf '%s\n' 'SHADOWOPS_CHRONICLES_API_HOST_WRAPPER_INSTALLED'
