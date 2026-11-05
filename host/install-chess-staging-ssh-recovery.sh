#!/usr/bin/env bash
# Install an independent supervised connector without stopping the existing one.
set -euo pipefail
[[ $# == 0 && $(id -u) == 0 ]] || exit 64
readonly root=/var/lib/ocarun/.cache/chess-studio-cloudflared
readonly bin="$root/cloudflared-2026.9.1"
readonly token="$root/token"
readonly expected=3d97437c71848bd8df68041e12436b484a661d95073ea1937f01a845ce88faa3
readonly unit=shadowops-chess-staging-ssh-recovery.service
[[ -d "$root" && ! -L "$root" && -f "$bin" && ! -L "$bin" && -x "$bin" && -f "$token" && ! -L "$token" ]] || exit 65
[[ $(stat -c '%U:%a' "$root") == ocarun:700 && $(stat -c '%U:%a' "$token") == ocarun:600 ]] || exit 65
printf '%s  %s\n' "$expected" "$bin" | sha256sum --check --status || exit 65
work="$(mktemp -d /tmp/shadowops-tunnel-unit.XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
cat > "$work/$unit" <<'UNIT'
[Unit]
Description=ShadowOps Chess staging recovery connector
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
ConditionPathExists=/var/lib/ocarun/.cache/chess-studio-cloudflared/token
ConditionPathExists=/var/lib/ocarun/.cache/chess-studio-cloudflared/cloudflared-2026.9.1

[Service]
Type=simple
User=ocarun
ExecStart=/var/lib/ocarun/.cache/chess-studio-cloudflared/cloudflared-2026.9.1 tunnel --no-autoupdate --loglevel info run --token-file /var/lib/ocarun/.cache/chess-studio-cloudflared/token
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
systemd-analyze verify "$work/$unit"
if [[ -e "/etc/systemd/system/$unit" || -L "/etc/systemd/system/$unit" ]]; then
  [[ -f "/etc/systemd/system/$unit" && ! -L "/etc/systemd/system/$unit" ]] || exit 65
  cmp -s "$work/$unit" "/etc/systemd/system/$unit" || exit 65
else
  install -o root -g root -m 0644 "$work/$unit" "/etc/systemd/system/$unit"
fi
systemctl daemon-reload
systemctl enable --now "$unit"
systemctl is-enabled --quiet "$unit"
systemctl is-active --quiet "$unit"
for _ in {1..30}; do
  if journalctl --no-pager --quiet -u "$unit" -n 100 | grep -F 'Registered tunnel connection' >/dev/null; then
    printf '%s\n' 'CHESS_STAGING_SSH_RECOVERY_UNIT_CONNECTED'
    exit 0
  fi
  sleep 1
done
printf '%s\n' 'CHESS_STAGING_SSH_RECOVERY_UNIT_UNCONFIRMED' >&2
exit 1
