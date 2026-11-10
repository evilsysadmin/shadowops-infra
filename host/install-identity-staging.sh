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
for file in host/identity-staging-deploy.py host/identity-staging.sudoers scripts/identity_staging_bundle.py \
            host/identity-staging-backup.py scripts/identity_staging_backup.py \
            host/identity-staging-backup.service host/identity-staging-backup.timer \
            scripts/shared_a1_host_guard.py compose.identity.staging.yaml \
            host/identity-atlas-staging-prepare.py host/identity-atlas-staging-backup.py host/identity-atlas-staging-preflight.py host/identity-atlas-staging-canary.py host/identity-atlas-staging-deploy.py host/identity-atlas-staging-lock.py host/identity-atlas-staging-snooker-config.py \
            host/identity-atlas-staging-backup.service host/identity-atlas-staging-backup.timer \
            scripts/identity_staging_atlas.py scripts/identity_staging_atlas_custody.py \
            scripts/identity_staging_atlas_backup.py scripts/identity_staging_atlas_policy.py scripts/identity_staging_atlas_admission.py scripts/identity_staging_atlas_journey.py scripts/identity_staging_atlas_restore.py scripts/identity_staging_atlas_transition.py scripts/identity_staging_atlas_lock.py scripts/identity_staging_atlas_snooker_config.py \
            compose.identity.atlas.staging.yaml; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  (( (8#$(stat -c %a "$source") & 8#022) == 0 )) || exit 66
done
visudo -cf "$repo/host/identity-staging.sudoers" >/dev/null
for destination in /etc/shadowops/identity-staging /var/lib/shadowops/identity-staging \
                   /usr/local/sbin/shadowops-identity-staging-backup \
                   /usr/local/lib/shadowops/identity_staging_backup.py \
                   /etc/systemd/system/shadowops-identity-staging-backup.service \
                   /etc/systemd/system/shadowops-identity-staging-backup.timer \
                   /etc/sudoers.d/105-shadowops-identity-staging \
                   /usr/local/sbin/shadowops-identity-staging /usr/local/lib/shadowops/identity_staging_bundle.py \
                   /usr/local/sbin/shadowops-identity-atlas-prepare /usr/local/sbin/shadowops-identity-atlas-backup /usr/local/sbin/shadowops-identity-atlas-preflight /usr/local/sbin/shadowops-identity-atlas-canary /usr/local/sbin/shadowops-identity-atlas-deploy /usr/local/sbin/shadowops-identity-atlas-lock /usr/local/sbin/shadowops-identity-atlas-snooker-config \
                   /usr/local/lib/shadowops/identity_staging_atlas.py /usr/local/lib/shadowops/identity_staging_atlas_custody.py \
                   /usr/local/lib/shadowops/identity_staging_atlas_backup.py /usr/local/lib/shadowops/identity_staging_atlas_policy.py /usr/local/lib/shadowops/identity_staging_atlas_admission.py /usr/local/lib/shadowops/identity_staging_atlas_journey.py /usr/local/lib/shadowops/identity_staging_atlas_restore.py /usr/local/lib/shadowops/identity_staging_atlas_transition.py /usr/local/lib/shadowops/identity_staging_atlas_lock.py /usr/local/lib/shadowops/identity_staging_atlas_snooker_config.py \
                   /etc/shadowops/identity-staging/atlas-compose.yaml \
                   /etc/systemd/system/identity-atlas-staging-backup.service \
                   /etc/systemd/system/identity-atlas-staging-backup.timer; do
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
install -o root -g root -m 0644 "$repo/compose.identity.atlas.staging.yaml" /etc/shadowops/identity-staging/atlas-compose.yaml
for module in identity_staging_atlas identity_staging_atlas_custody identity_staging_atlas_backup identity_staging_atlas_policy identity_staging_atlas_admission identity_staging_atlas_journey identity_staging_atlas_restore identity_staging_atlas_transition identity_staging_atlas_lock identity_staging_atlas_snooker_config; do
  install -o root -g root -m 0644 "$repo/scripts/$module.py" "/usr/local/lib/shadowops/$module.py"
done
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-prepare.py" /usr/local/sbin/shadowops-identity-atlas-prepare
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-preflight.py" /usr/local/sbin/shadowops-identity-atlas-preflight
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-canary.py" /usr/local/sbin/shadowops-identity-atlas-canary
# Installed only by the explicit authorized SSH/bootstrap path; no staging mutation on install.
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-deploy.py" /usr/local/sbin/shadowops-identity-atlas-deploy
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-lock.py" /usr/local/sbin/shadowops-identity-atlas-lock
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-snooker-config.py" /usr/local/sbin/shadowops-identity-atlas-snooker-config
install -o root -g root -m 0755 "$repo/host/identity-atlas-staging-backup.py" /usr/local/sbin/shadowops-identity-atlas-backup
# Install, but do not enable: cutover must first prove Atlas backup/restore.
install -o root -g root -m 0644 "$repo/host/identity-atlas-staging-backup.service" /etc/systemd/system/identity-atlas-staging-backup.service
install -o root -g root -m 0644 "$repo/host/identity-atlas-staging-backup.timer" /etc/systemd/system/identity-atlas-staging-backup.timer
install -o root -g root -m 0644 "$repo/scripts/identity_staging_bundle.py" /usr/local/lib/shadowops/identity_staging_bundle.py
install -o root -g root -m 0644 "$repo/scripts/shared_a1_host_guard.py" /usr/local/lib/shadowops/shared_a1_host_guard.py
install -o root -g root -m 0755 "$repo/host/identity-staging-deploy.py" /usr/local/sbin/shadowops-identity-staging
install -o root -g root -m 0644 "$repo/scripts/identity_staging_backup.py" /usr/local/lib/shadowops/identity_staging_backup.py
install -o root -g root -m 0755 "$repo/host/identity-staging-backup.py" /usr/local/sbin/shadowops-identity-staging-backup
install -o root -g root -m 0644 "$repo/host/identity-staging-backup.service" /etc/systemd/system/shadowops-identity-staging-backup.service
install -o root -g root -m 0644 "$repo/host/identity-staging-backup.timer" /etc/systemd/system/shadowops-identity-staging-backup.timer
systemctl daemon-reload
systemctl enable --now shadowops-identity-staging-backup.timer
# Delegate only this argument-validating staging wrapper after policy exists.
install -o root -g root -m 0440 "$repo/host/identity-staging.sudoers" /etc/sudoers.d/105-shadowops-identity-staging
visudo -cf /etc/sudoers.d/105-shadowops-identity-staging >/dev/null
printf '%s\n' IDENTITY_STAGING_OPERATOR_WRAPPER_INSTALLED
