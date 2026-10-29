# ShadowOps Identity · standalone Go signing core (P0)

Tracking: [ShadowOps Identity P0 #287](https://github.com/evilsysadmin/shadowops-infra/issues/287).

This directory is a **temporary extraction workspace in Infra**, pending creation of the dedicated `evilsysadmin/shadowops-identity` repository. It is an independently buildable Go module without a dependency on Chess Studio, Chronicles, MongoDB or other products.

The initial `core` package supports strict `staging` and `production` issuer identities, Ed25519 signing keys supplied by an explicit caller, public JWKS, and a **synthetic probe** signed JWT. Its audience is always `shadowops-identity-probe`, its subject is a random `probe:` identifier, and the validity is 120 seconds. The caller cannot set an application audience or actual user subject. A staging token is rejected by the production verifier even when key material is accidentally reused (and the separation validator explicitly rejects reused keys). No signing seed is checked in, and `New` never derives one from Chess Studio's `JWT_SECRET`.

## Deliberate limitations

- **NO account registration, password verification, sessions, login, refresh, logout, user access tokens or authorization.**
- **NO HTTP server, DNS name, published container, database, secret store connection or deployment.**
- **NO OIDC claims or conformance**; tests only establish a small cryptographic trust boundary.
- A green test does **not** mean ShadowOps Identity staging or production is online.
- Do not copy the synthetic fixture seed from the tests into any real deployment. Future keys must come from separate environment-scoped secret stores.
- Do not allow Chess Studio/Chronicles/CKA to trust the synthetic probe audience.

Run `cd services/identity && go test -race ./... && go vet ./...`. The Infra CI runs the suite independently, without Cloudflare or OCI secrets. The module can be moved to its own repository with no runtime dependencies.

The next stage is a **staging-only, nonpublic runtime** using independent persistent accounts and rotation key management, then audited compatibility migration from the Chess Studio IdP. Do not enable new user auth or production migration until account linkage, session revocation, rate limiting, CSRF/CORS, backup/restore, rollout and rollback tests are complete.

## P0.2 bootstrap: local-only staging HTTP process

The executable `go run ./cmd/staging` is intentionally restricted to **127.0.0.1:9187** and only starts with `IDENTITY_ENVIRONMENT=staging` plus `IDENTITY_STAGING_SEED_FILE` pointing to an **absolute, regular, private-permission (0600/0400) 32-byte file**. Use a separately generated ephemeral test key for controlled local smoke; never reuse Chess Studio secrets or check key files into Git.

Exactly three GET routes exist:

- `/livez`: HTTP 200 (process alive, not an auth health check)
- `/api/identity/jwks`: HTTP 200 with public-only Ed25519 JWKS, no-store
- `/readyz`: **always HTTP 503**; account/session and security gates are not yet implemented

All login, token exchange, registration, session and authorization routes return 404. POST to JWKS returns 405. The process has no ingress/Tunnel/Pages route, no database, no user tokens and no production environment. The seed file's parent directory must be owned and protected by the operator; the loader rejects directly visible symlinks and unsafe file modes but is not a general-purpose secret-management solution. Replace the temporary seed-file mechanism with the dedicated per-environment secret store before any actual service deployment.

Run `go test -race ./... && go vet ./...` from `services/identity`. This is **not** a staging deployment or an IdP ready for users; it only proves a hardened local JWKS/liveness process while work continues on accounts, sessions, rotation and rollback.
