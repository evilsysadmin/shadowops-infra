#!/usr/bin/env bash
# Disposable localhost-only authenticated MongoDB RBAC gate for GitHub Actions.
# Generates independent random credentials; never connects to real databases.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
key_dir="$(mktemp -d)"
cleanup() {
  docker rm -f identity-rbac-ci >/dev/null 2>&1 || true
  sudo rm -rf "$key_dir"
}
trap cleanup EXIT
root_pass="$(openssl rand -hex 24)"
maint_pass="$(openssl rand -hex 24)"
exec_pass="$(openssl rand -hex 24)"
role_exec_pass="$(openssl rand -hex 24)"
for secret in "$root_pass" "$maint_pass" "$exec_pass" "$role_exec_pass"; do
  echo "::add-mask::$secret"
done

# The replica set's internal keyfile is synthetic and disposable.
openssl rand -base64 500 > "$key_dir/mongo-keyfile"
chmod 400 "$key_dir/mongo-keyfile"
sudo chown 999:999 "$key_dir/mongo-keyfile"
chmod 755 "$key_dir"

docker run -d --name identity-rbac-ci --network host \
  -e MONGO_INITDB_ROOT_USERNAME=identity_test_root \
  -e MONGO_INITDB_ROOT_PASSWORD="$root_pass" \
  -v "$key_dir/mongo-keyfile:/etc/identity-rbac-keyfile:ro" \
  mongo:7.0 --replSet identity-rbac-rs --keyFile /etc/identity-rbac-keyfile \
  --bind_ip 127.0.0.1 --port 27019

for attempt in {1..90}; do
  if docker exec identity-rbac-ci mongosh --quiet --norc \
    "mongodb://127.0.0.1:27019/?directConnection=true" \
    --eval 'print(db.adminCommand({ping:1}).ok)' 2>/dev/null | grep -qx 1; then
    break
  fi
  if [[ "$attempt" == 90 ]]; then
    docker logs identity-rbac-ci --tail 80
    exit 1
  fi
  sleep 1
done

auth_eval='const a=db.getSiblingDB("admin").auth("identity_test_root",process.env.IDENTITY_RBAC_ROOT_PASS); if (!(a === true || a === 1 || a.ok === 1)) throw new Error("root test auth failed");'
docker exec -e IDENTITY_RBAC_ROOT_PASS="$root_pass" identity-rbac-ci \
  mongosh --quiet --norc "mongodb://127.0.0.1:27019/?directConnection=true" \
  --eval "$auth_eval rs.initiate({_id:'identity-rbac-rs',members:[{_id:0,host:'127.0.0.1:27019'}]})"

for attempt in {1..90}; do
  if docker exec -e IDENTITY_RBAC_ROOT_PASS="$root_pass" identity-rbac-ci \
    mongosh --quiet --norc "mongodb://127.0.0.1:27019/?directConnection=true" \
    --eval "$auth_eval print(db.hello().isWritablePrimary)" 2>/dev/null | grep -qx true; then
    break
  fi
  if [[ "$attempt" == 90 ]]; then
    docker logs identity-rbac-ci --tail 80
    exit 1
  fi
  sleep 1
done

docker cp "$repo_root/services/identity/rbac/seed.mongosh.js" identity-rbac-ci:/tmp/identity-rbac-seed.js
docker cp "$repo_root/services/identity/rbac/verify.mongosh.js" identity-rbac-ci:/tmp/identity-rbac-verify.js

docker exec -e IDENTITY_RBAC_ROOT_PASS="$root_pass" \
  -e IDENTITY_RBAC_MAINT_PASS="$maint_pass" \
  -e IDENTITY_RBAC_EXEC_PASS="$exec_pass" \
  -e IDENTITY_RBAC_ROLE_EXEC_PASS="$role_exec_pass" identity-rbac-ci \
  mongosh --quiet --norc "mongodb://127.0.0.1:27019/?directConnection=true" \
  --eval "$auth_eval load('/tmp/identity-rbac-seed.js')"

docker exec -e IDENTITY_RBAC_ROOT_PASS="$root_pass" \
  -e IDENTITY_RBAC_MAINT_PASS="$maint_pass" \
  -e IDENTITY_RBAC_EXEC_PASS="$exec_pass" \
  -e IDENTITY_RBAC_ROLE_EXEC_PASS="$role_exec_pass" identity-rbac-ci \
  mongosh --quiet --norc "mongodb://127.0.0.1:27019/?directConnection=true" \
  --eval "$auth_eval load('/tmp/identity-rbac-verify.js')"
