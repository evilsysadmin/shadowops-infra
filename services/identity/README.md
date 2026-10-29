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
