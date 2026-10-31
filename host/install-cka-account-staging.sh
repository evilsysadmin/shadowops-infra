#!/usr/bin/env bash
# Explicit root operator installation only; never invoke via OCI Run Command.
set -euo pipefail
[[ "${EUID:-$(id -u)}" == 0 && $# == 1 && "$1" =~ ^[a-f0-9]{40}$ ]] || exit 77
readonly repo=/opt/shadowops-infra
readonly expected="$1"
# Includes clean exact-SHA/root ownership checks and the updated consumer schema.
bash "$repo/host/install-shared-identity-staging.sh" "$expected"
for file in host/cka-account-staging-deploy.py host/cka-account-staging.sudoers scripts/cka_account_contract.py compose.cka-account.staging.yaml; do
  source="$repo/$file"
  [[ -f "$source" && ! -L "$source" && "$(stat -c %u "$source")" == 0 ]] || exit 66
  (( (8#$(stat -c %a "$source") & 8#022) == 0 )) || exit 66
done
visudo -cf "$repo/host/cka-account-staging.sudoers" >/dev/null
for target in /etc/shadowops/cka-account-staging /var/lib/shadowops/cka-account-staging /usr/local/sbin/shadowops-cka-account-staging /usr/local/lib/shadowops/cka_account_contract.py /etc/sudoers.d/106-shadowops-cka-account-staging; do
  [[ ! -L "$target" ]] || exit 66
done
install -d -o root -g root -m 0700 /etc/shadowops/cka-account-staging /var/lib/shadowops/cka-account-staging
install -o root -g root -m 0644 "$repo/compose.cka-account.staging.yaml" /etc/shadowops/cka-account-staging/compose.yaml
install -o root -g root -m 0644 "$repo/scripts/cka_account_contract.py" /usr/local/lib/shadowops/cka_account_contract.py
install -o root -g root -m 0755 "$repo/host/cka-account-staging-deploy.py" /usr/local/sbin/shadowops-cka-account-staging
python3 - "$expected" <<'PY'
import hashlib,json,os,sys,tempfile
from pathlib import Path
paths=['/usr/local/sbin/shadowops-cka-account-staging','/usr/local/lib/shadowops/cka_account_contract.py','/usr/local/lib/shadowops/identity_staging_bundle.py','/etc/shadowops/cka-account-staging/compose.yaml']
value={'schema':1,'source_sha':sys.argv[1],'files':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}}
root=Path('/var/lib/shadowops/cka-account-staging');fd,name=tempfile.mkstemp(dir=root,prefix='.policy-')
os.fchmod(fd,0o400)
with os.fdopen(fd,'w') as out:json.dump(value,out)
os.replace(name,root/'policy.json')
PY
install -o root -g root -m 0440 "$repo/host/cka-account-staging.sudoers" /etc/sudoers.d/106-shadowops-cka-account-staging
visudo -cf /etc/sudoers.d/106-shadowops-cka-account-staging >/dev/null
/usr/local/sbin/shadowops-cka-account-staging inspect
printf '%s\n' CKA_ACCOUNT_STAGING_OPERATOR_INSTALLED
