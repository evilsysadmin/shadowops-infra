# Configured staging TLS service

`cmd/service-staging` wires the real central account/browser handler and trusted
freshness RPC. It is separate from the older `cmd/staging` bootstrap, whose
readiness remains 503. No listener is started by a library import.

The new executable requires `IDENTITY_STAGING_CONFIG_FILE` naming an absolute,
regular, non-symlink JSON file, with no group/other permission bits and at most
128 KiB. The operator must protect its parent directory and make the mounted
file readable only by container UID 65532. No secret is passed on the command
line or logged. Schema (values below are descriptions, not usable secrets):

| Field | Required value |
| --- | --- |
| environment | staging |
| mongo_uri | TLS Mongo URI with the dedicated staging application user |
| mongo_ca_pem | Private Mongo CA PEM, or empty for normal system trust |
| signing_seed | Canonical base64url of 32 independently random staging bytes |
| tls_certificate_pem | Valid server certificate chain with exact staging IdP DNS SAN |
| tls_private_key_pem | Matching private key, separate from JWT signing key |
| consumers | Application → independent 256-bit soc1_ server credential map |
| chronicles_admin_alias_credential | Optional dedicated 256-bit `soa1_` credential for read-only Chronicles Admin alias resolution; never the existing `soc1_` freshness secret |

Only explicitly configured consumers can obtain browser tokens or be selected
as login return targets. Candidate origins for other projects stay disabled.

The URI cannot choose another database or disable TLS/certificate validation.
The effective database is always `shadowops_identity_staging`. Before creating
indexes or enabling routes, startup checks a live authenticated user, a writable
replica set, and the **effective Mongo privileges**, including inherited roles.
It rejects admin/cluster privileges, database wildcards, other collections,
unapproved actions, unauthenticated clients and incomplete application roles.
The required custom role has exactly these collection-scoped actions:

| Collection | Actions |
| --- | --- |
| pending_accounts | find, insert, update, createIndex, listIndexes |
| sessions | find, insert, update, remove, createIndex, listIndexes |
| staging_cka_tokens | find, insert, update, createIndex, listIndexes |

The historical account/token collection names remain compatible with existing
staging fixtures. The service creates its unique/session TTL indexes and the
token expiry TTL index; authorization always checks expiration independently.
No database root credential or CA private key belongs in this service bundle.

TLS listens on :9443 inside the private container network (an operator can
explicitly select internal port 443). Origin Host must always be
`id-staging.shadowops.dpdns.org`; forwarded headers cannot assert TLS or host.
Healthcheck verifies TLS using the configured certificate chain and SNI.
`/livez` is process liveness; `/readyz` checks replica/read availability and only
returns 200 after the configured runtime has initialized successfully.
`/api/identity/release` exposes only service/environment/source SHA. CI stamps
the immutable source SHA; a development value is not deployment evidence.
SIGTERM drains HTTP and disconnects Mongo with bounded shutdown.

The scratch image runs only the statically compiled Go binary and CA roots as
UID/GID 65532. Go 1.27.3 and current cryptography/text dependencies match the
Chronicles security floor. The image workflow tests real TLS/SCRAM Mongo startup,
rejects root/readWrite/incomplete clients and untrusted certificates, exercises
signup/login/token/freshness/logout under the narrow role, scans source and both
native binaries, then publishes and attests SHA-pinned amd64/arm64 images only
from protected main. It does not receive OCI/Cloudflare credentials or deploy.

Operational handoff still belongs to Infra: isolated Mongo persistence/role,
independent secret custody, certificate/consumer rotation, backup and safe
restore, private networks, tunnel/DNS, image-digest/provenance admission, actual
Chronicles login/save/logout/revocation and legacy-namespace preflight. The
existing product logins and production are unchanged by this runtime. CI's
`runtime/ci.sh` is **only a disposable localhost fixture**, never a deployment
or a source of credentials to copy into staging.


## Optional Chronicles Admin account aliases (staging only)

`POST /api/identity/admin-aliases` is **disabled by default**. It is mounted
only when a separate `chronicles_admin_alias_credential` is explicitly placed in
the protected Identity service bundle and the service is restarted. Operators
must provision this credential independently to **only the Chronicles API
backend**, not to the browser, Cloudflare Pages, other products or their
freshness RPC. The credential is not an admin login role: Chronicles must
authenticate and authorize the requesting account as a roster administrator
*before* it makes this server-to-server call. Do not bind it to `ADMIN_USERNAMES="*"`.

The internal HTTPS request (exact pinned IdP host, no Origin/Cookie/CORS) is:

```http
POST /api/identity/admin-aliases HTTP/1.1
Host: id-staging.shadowops.dpdns.org
Authorization: Bearer <independent soa1_ operator secret>
Content-Type: application/json

{"subjects":["<verified staging UUIDv4>"]}
```

At most 40 unique canonical UUIDv4 subjects are accepted. The reply is
`{"aliases":{"<subject>":"<native-account-name>"}}`; unavailable,
suspended, non-native, wrong-environment or unknown accounts are **omitted**.
The store projection contains only immutable subject and `alias_key`:
password hashes, sessions, emails, roles and recovery data are never selected.
The caller must fall back to the abbreviated technical ID if a subject is
missing or the authority is unavailable. The endpoint denies cookie/origin
requests, malformed and excess bodies, unauthorized credentials and unsupported
methods. It is limited globally to 30 successful-credential requests/minute
and 40 subjects/request, with a two-second storage deadline; responses are
non-cacheable and have no browser CORS. Error bodies never leak database data.

The rollout is a **separate operator action**: no alias secret is in Git,
no existing staging bundle is automatically changed, and this code does not
wire the Chronicles API client. Before enabling, review the roster admin
authorization, credential distribution, rollback and audit contract in
shadowops-infra issue #374. No production service is modified by this feature.
