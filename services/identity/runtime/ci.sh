#!/usr/bin/env bash
# Disposable TLS+SCRAM replica set. No real DB, credentials, host chown or sudo.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cert_dir="$(mktemp -d /tmp/identity-runtime-ci-XXXXXXXX)"
container_name="identity-runtime-ci-$$"
cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  rm -rf "$cert_dir"
}
trap cleanup EXIT
python3 - <<'PY'
import socket
sock=socket.socket()
assert sock.connect_ex(('127.0.0.1',27019))!=0, 'Refusing occupied runtime fixture port'
sock.close()
PY
root_pass="$(openssl rand -hex 24)"
app_pass="$(openssl rand -hex 24)"
broad_pass="$(openssl rand -hex 24)"
incomplete_pass="$(openssl rand -hex 24)"
openssl rand -base64 500 > "$cert_dir/keyfile"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj /CN=identity-runtime-disposable-ca -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$cert_dir/mongo.key" -out "$cert_dir/mongo.csr" >/dev/null 2>&1
cat > "$cert_dir/mongo.ext" <<'EOF'
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth,clientAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EOF
openssl x509 -req -in "$cert_dir/mongo.csr" -CA "$cert_dir/ca.pem" -CAkey "$cert_dir/ca.key" \
  -CAcreateserial -days 1 -sha256 -extfile "$cert_dir/mongo.ext" -out "$cert_dir/mongo.crt" >/dev/null 2>&1
cat "$cert_dir/mongo.key" "$cert_dir/mongo.crt" > "$cert_dir/mongo.pem"

# Copy private fixture files inside the disposable container before dropping to
# the Mongo UID. Never chown arbitrary host files or touch an existing volume.
docker run --rm -d --name "$container_name" --network host --tmpfs /data/db:rw,size=512m \
  -v "$cert_dir:/fixtures:ro" --entrypoint bash mongo:7.0 -c '
    cp /fixtures/keyfile /tmp/keyfile
    cp /fixtures/mongo.pem /tmp/mongo.pem
    cp /fixtures/ca.pem /tmp/ca.pem
    chown mongodb:mongodb /tmp/keyfile /tmp/mongo.pem /data/db
    chmod 400 /tmp/keyfile /tmp/mongo.pem
    exec gosu mongodb mongod --replSet identity-runtime-rs --keyFile /tmp/keyfile \
      --bind_ip 127.0.0.1 --port 27019 --wiredTigerCacheSizeGB 0.25 \
      --tlsMode requireTLS --tlsCertificateKeyFile /tmp/mongo.pem --tlsCAFile /tmp/ca.pem \
      --tlsAllowConnectionsWithoutCertificates
  '
mongo_eval() {
  docker exec "$container_name" mongosh --quiet --norc --tls --tlsCAFile /tmp/ca.pem \
    'mongodb://127.0.0.1:27019/?directConnection=true' --eval "$1"
}
ready=false
for attempt in {1..60}; do
  if mongo_eval 'print(db.adminCommand({ping:1}).ok)' 2>/dev/null | grep -qx 1; then ready=true; break; fi
  sleep 1
done
[[ "$ready" == true ]]
mongo_eval 'print(rs.initiate({_id:"identity-runtime-rs",members:[{_id:0,host:"127.0.0.1:27019"}]}).ok)'
ready=false
for attempt in {1..60}; do
  if mongo_eval 'print(db.hello().isWritablePrimary)' 2>/dev/null | grep -qx true; then ready=true; break; fi
  sleep 1
done
[[ "$ready" == true ]]
docker exec -e RUNTIME_ROOT_PASS="$root_pass" "$container_name" mongosh --quiet --norc --tls --tlsCAFile /tmp/ca.pem \
  'mongodb://127.0.0.1:27019/?directConnection=true' \
  --eval 'print(db.getSiblingDB("admin").createUser({user:"identity_root",pwd:process.env.RUNTIME_ROOT_PASS,roles:[{role:"root",db:"admin"}]}).ok)'
docker cp "$repo_root/services/identity/runtime/seed-runtime-fixture.mongosh.js" "$container_name:/tmp/seed.js" >/dev/null
docker exec -e RUNTIME_ROOT_PASS="$root_pass" -e RUNTIME_APP_PASS="$app_pass" \
  -e RUNTIME_BROAD_PASS="$broad_pass" -e RUNTIME_INCOMPLETE_PASS="$incomplete_pass" \
  "$container_name" mongosh --quiet --norc --tls --tlsCAFile /tmp/ca.pem \
  'mongodb://127.0.0.1:27019/?directConnection=true' --eval 'load("/tmp/seed.js")'

suffix='?replicaSet=identity-runtime-rs&directConnection=true&tls=true&authSource=shadowops_identity_staging'
export IDENTITY_RUNTIME_MONGO_URL="mongodb://identity_runtime:$app_pass@127.0.0.1:27019/shadowops_identity_staging$suffix"
export IDENTITY_RUNTIME_BROAD_URI="mongodb://identity_broad:$broad_pass@127.0.0.1:27019/shadowops_identity_staging$suffix"
export IDENTITY_RUNTIME_INCOMPLETE_URI="mongodb://identity_incomplete:$incomplete_pass@127.0.0.1:27019/shadowops_identity_staging$suffix"
export IDENTITY_RUNTIME_ADMIN_URI="mongodb://identity_root:$root_pass@127.0.0.1:27019/shadowops_identity_staging?replicaSet=identity-runtime-rs&directConnection=true&tls=true&authSource=admin"
export IDENTITY_RUNTIME_MONGO_CA_FILE="$cert_dir/ca.pem"
cd "$repo_root/services/identity"
go test -race -count=1 -v ./runtime -run 'TestServiceRuntime'
