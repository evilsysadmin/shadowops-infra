#!/usr/bin/env bash
# Operator SSH installation only. Never execute this script via OCI Run Command.
set -euo pipefail
[[ "${EUID:-$(id -u)}" == 0 && $# == 1 && "$1" =~ ^[a-f0-9]{40}$ ]] || exit 77
readonly repo=/opt/shadowops-infra
readonly expected="$1"
for path in /opt "$repo" "$repo/.git" "$repo/host" "$repo/scripts"; do
  [[ -d "$path" && ! -L "$path" && "$(stat -c %u "$path")" == 0 ]] || exit 66
  (( (8#$(stat -c %a "$path") & 8#022) == 0 )) || exit 66
done
[[ "$(git -C "$repo" rev-parse HEAD)" == "$expected" ]] || exit 65
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ]] || exit 65
for file in host/identity-staging-deploy.py scripts/identity_staging_bundle.py \
            scripts/shared_a1_host_guard.py compose.identity.staging.yaml; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  (( (8#$(stat -c %a "$source") & 8#022) == 0 )) || exit 66
done
for destination in /etc/shadowops/identity-staging /var/lib/shadowops/identity-staging \
                   /usr/local/sbin/shadowops-identity-staging /usr/local/lib/shadowops/identity_staging_bundle.py; do
  [[ ! -L "$destination" ]] || exit 66
done
install -d -o root -g root -m 0755 /usr/local/lib/shadowops /opt/shadowops
install -d -o root -g root -m 0700 /etc/shadowops/identity-staging /var/lib/shadowops/identity-staging
readonly venv=/opt/shadowops/oci-venv
[[ ! -L "$venv" ]] || exit 66
if [[ ! -x "$venv/bin/python" ]]; then python3 -m venv "$venv"; fi
"$venv/bin/pip" install --disable-pip-version-check --quiet 'oci==2.185.2'
chown -R root:root "$venv"
chmod -R go-w "$venv"
install -o root -g root -m 0644 "$repo/compose.identity.staging.yaml" /etc/shadowops/identity-staging/compose.yaml
install -o root -g root -m 0644 "$repo/scripts/identity_staging_bundle.py" /usr/local/lib/shadowops/identity_staging_bundle.py
install -o root -g root -m 0644 "$repo/scripts/shared_a1_host_guard.py" /usr/local/lib/shadowops/shared_a1_host_guard.py
install -o root -g root -m 0755 "$repo/host/identity-staging-deploy.py" /usr/local/sbin/shadowops-identity-staging
# No OCI-agent sudo policy is installed by this first staging bootstrap.
printf '%s\n' IDENTITY_STAGING_OPERATOR_WRAPPER_INSTALLED
