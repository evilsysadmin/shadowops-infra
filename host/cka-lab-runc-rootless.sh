#!/bin/sh
# runc is spawned with a reduced environment by containerd. Re-establish only
# the fixed user-session address; never let UID 0 in a user namespace select
# the host system manager through rootful auto-detection.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
. /etc/cka-lab-staging/runc.env
case "$CKA_PARENT_UID" in ''|*[!0-9]*) exit 77;; esac
test "$CKA_PARENT_UID" -gt 0
awk -v expected="$CKA_PARENT_UID" 'NR==1 {if ($1!=0 || $2!=expected || $3!=1) exit 1; seen=1} END {if(!seen) exit 1}' /proc/self/uid_map
XDG_RUNTIME_DIR="/run/user/$CKA_PARENT_UID"
DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
export XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
exec "$CKA_RUNC" --rootless=true "$@"
