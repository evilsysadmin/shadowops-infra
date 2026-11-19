# ShadowOps Identity · separate production TLS bootstrap (not activated)

This is a **deliberately unready** first production-only runtime milestone.
It is **not** a user-facing identity provider and cannot authenticate anyone.

## Security and architecture

- The executable \`services/identity/cmd/service-production\` is distinct from
  \`cmd/service-staging\`. It does **not** reuse the staging Mongo database,
  cookie, issuer, signing key, user accounts or service proof.
- Configuration is read only from an explicitly named, absolute private
  \`IDENTITY_PRODUCTION_CONFIG_FILE\` (regular file, not symlink, no group or
  world permissions, bounded JSON, no unknown keys/trailing documents).
- \`environment\` must be \`production\`, the issuer derived by
  \`core.New("production", seed)\` is \`https://id.shadowops.dpdns.org\`, and
  the certificate is valid for exactly \`id.shadowops.dpdns.org\`.
- Mongo connection data must name \`shadowops_identity_production\`, have
  credentials, TLS enabled, an explicit CA and no insecure TLS options.
  This is an **offline contract check**; no Mongo connection or RBAC
  verification occurs yet.
- Only the production \`bridgesquad\` audience is admitted in this initial
  bundle. It uses its own canonical \`soc1_\` consumer proof. Signing key,
  TLS private key and consumer credential must not be interchangeable.
  Distinct custody from staging is still an operator provisioning requirement.
- **No credential/session/refresh/revocation/JWKS issuance is available.**
  Even with a valid bundle, \`/readyz\`, \`/api/identity/jwks\`,
  \`/login?app=bridgesquad\` and all Identity API routes return HTTP 503.
  Only \`GET /livez\` over the exact HTTPS production host returns 200;
  its body explicitly states that auth is disabled.
- \`cmd/service-production\` has no default start behavior. \`preflight\`
  validates the bundle; \`serve-unready\` is an **explicit opt-in** to a
  TLS listener at :9443, still entirely unready for authentication.
- There is **no production container deployment, Cloudflare/DNS write,
  OCI mutation or secret provisioning** in this change. The test workflow
  runs offline Go/Race/Vet and builds amd64/arm64 executables without publishing.

Do **not** point \`id.shadowops.dpdns.org\` or
\`bridgesquad.shadowops.dpdns.org\` at this bootstrap. It cannot sign
tokens for users, confirm account state or perform authoritative freshness
checks, and the existing game must continue to deny guests.

## Next increments required before any activation

Add an independent production Mongo issuer and atomic account/session
transactions, production-native user account handling, per-consumer signed
EdDSA tokens, authoritative freshness/revocation and isolated service proof.
Review least-privilege production Mongo roles, implement real browser/TLS
login with CSRF controls, then test an authenticated browser login and
immediate revocation end-to-end before provisioning the protected Cloudflare
binding or changing DNS.

Tracked in [Identity P0 #287](https://github.com/evilsysadmin/shadowops-infra/issues/287)
and [Bridge Squad activation #611](https://github.com/evilsysadmin/shadowops-infra/issues/611).
