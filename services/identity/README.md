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

## P0.2 session lifecycle domain (not wired to HTTP)

The `session` Go package now defines an opaque-handle lifecycle and a **persistent Store interface** for future isolated staging accounts. After credential validation (still **not implemented**), the server may issue a 256-bit CSPRNG handle for a validated immutable UUIDv4 subject. Only environment-separated SHA-256 digests of handles may be stored. Handles have a **24-hour absolute TTL** that refresh cannot extend. Refresh requires an **atomic compare-and-swap**, invalidates the previous handle, and rejects replay or concurrent losers. Logout revokes one session; password changes, account deletion or security events must invoke `RevokeSubject` to revoke all sessions in that environment. Storage failures must fail closed, never log handles.

**No persistent driver yet.** The only in-memory implementation lives in `session_test.go` and cannot be imported by deployed applications. The existing local HTTP bootstrap is still *unchanged*: `/readyz` returns 503, no login/refresh/logout/token routes, no new cookies, no user sessions and no deployment. Tests cover concurrent refresh, expiry, revocation, cross-environment isolation, malformed handles, fail-closed storage and strict UUIDv4 subjects using synthetic fixtures. Run `cd services/identity && go test -race ./... && go vet ./...`.

The next PR must implement Mongo/Postgres with atomic `Swap`, unique digest indexes and explicit staging-only DB credentials plus integration tests; only after that should account migration, passwords/session-version revocation and HTTP flows be considered. Never use the test store as production persistence.

## P0.2 persistent staging session adapter

The `mongostore` Go package implements the `session.Store` interface against **exactly** `shadowops_identity_staging.sessions`. It refuses Mongo database names used by Chess Studio or production. The backend inserts only environment-separated digests (hex), subject UUIDs and timestamps — never raw session handles, passwords or keys.

`New` requires Mongo index creation to succeed before accepting sessions: a unique compound index on `environment,digest`, TTL index on `expires_at`, and a subject index for account-wide revocation. All writes request majority acknowledgement. Rotation is a **single conditional UpdateOne**, replacing the unique digest in place and preserving absolute expiration, environment and subject. This means competing refreshes have one winner even across worker processes, and concurrent logout cannot resurrect a document. Manager validation checks expiry independently; TTL cleanup is only garbage collection, not authorization.

The Mongo integration job uses an ephemeral `mongo:7` at 127.0.0.1; tests reject all other test URLs to avoid running destructive fixtures against shared databases. No live credentials are accepted. **The existing staging bootstrap is not wired to this adapter** and keeps `/readyz=503`; no login, user token, cookie or product access is enabled. The driver is staging-only by contract; production must receive distinct secrets, database role and a separately audited rollout.

**Not yet solved:** account persistence/migration, password hashing/verification, logout HTTP, DB TLS/secret ownership, backup and restore, actual OCI deployment, CORS/CSRF, abuse controls and end-to-end staging login. Green integration CI is not a deployment approval.

## P0.2 compatibility with existing Chess Studio password hashes

The independent `password` Go package verifies legacy Chess Studio `$argon2id$`, historical `$argon2i$`, and `$2a$`/`$2b$`/`$2y$` bcrypt hashes **without connecting to the Chess database**. Its regression fixture is the synthetic, Python-produced Chess Studio password parity corpus: 47 hashes, 197 password checks. It reproduces Python bcrypt's 72-byte truncation and argon2-cffi PHC encoding, including Unicode cases. `HashNew` generates **only Argon2id** using the existing 19 MiB, t=2, p=1, 16-byte salt and 32-byte output contract; no automatic rewriting of legacy password hashes occurs.

**Fail-closed resource protection:** before running any KDF, verifier enforces 4096-byte input cap, 256-byte encoded hash cap, Argon2 m=8–64 MiB, t=1–6, p=1–4, salt 8–64 bytes and output 16–64 bytes, and bcrypt cost 4–16. A legacy account outside these bounds must be reviewed and reset/migrated using an approved secure workflow; these checks intentionally decline unsafe legacy hashes rather than allowing password-based memory/CPU exhaustion.

No password hash or credential is retrieved from a live environment, copied to this repo or logged. There is **no Mongo accounts adapter, no password-based login, no user session issuance, no HTTP handler or account migration** here. Synthetic tests only; the bootstrap remains loopback-only and `/readyz=503`. Account import requires a separately reviewed, staging-only, reversible process with stable UUID subjects and password/session-version revocation.

## P0.2 staging pending account reservations

The `pendingaccounts` Go package provides **insert-only MongoDB reservations** in `shadowops_identity_staging.pending_accounts`. Each reservation has a canonical UUIDv4 `sub`, exactly **one** legacy source (`chess-studio` or `chronicles`), its original legacy username, a normalized alias key (`NFKC + casefold`), a review issue reference and the literal state `pending-review`. A unique index on `environment + source + alias_key` prevents two UUIDs claiming the same legacy account (including Unicode/case aliases). The unique Mongo `_id` prevents two products claiming the same UUID, even when a ticket URL matches.

This is **not an account import, login or approval**: an issue URL is a review reference and **does not prove ownership**. There is deliberately **no activation or multi-product merge method**, and no passwords/hashes, email, privileges, roles or sessions are stored in this collection. Existing product data and usernames remain unchanged. Manual verification and backed-up mapping will be required before building the approved-accounts store or implementing authentication. These documents contain usernames (personal data), so no production inputs are checked into Git or printed to logs.

Mongo integration tests use a disposable local-only `mongo:7` and prove index uniqueness, Unicode alias conflicts, same-name/different-product isolation, rejection of a shared `sub`, pending-only retrieval and refusal of all non-staging Mongo databases. The staging runtime remains disconnected, unpublished, and permanently `/readyz=503`; the CKA preview is still read-only.

## P0.2 two-person ownership review (offline, still no login)

The `pendingaccounts` package now permits **only** a one-way, atomic MongoDB state change from `pending-review` to `ownership-reviewed`, never to an active or login-enabled account. The reviewing store must be explicitly initialized with **two distinct Ed25519 public keys pinned by the trusted offline operator** (`NewReviewStore`). The normal `New` store has no authority to review and always rejects that operation. The keys must belong to separate review authorities and must never be supplied by a user request or plan file.

Both reviewers must independently sign exactly the same domain-separated JSON assertion for **staging**, UUIDv4 subject, legacy product, original username, issue review reference, SHA-256 evidence digest, one-time nonce, review timestamp, and short validity (maximum ten minutes). This provides accountable *attestation* of an out-of-band ownership review, **not proof that the underlying human review was performed correctly**: obtaining a GitHub issue URL, arbitrary evidence hash or signatures created by one operator does not suffice. Keep underlying evidence and private signing keys outside GitHub/CI and any browser. No production review keys, real dossiers or identities are included.

A single conditional Mongo `UpdateOne` matches the unchanged pending reservation, including the precise source/username/review reference, and changes only its state and non-secret audit fields. Replays, stale claims, mismatched sources, reused UUIDs and competing concurrent reviews are rejected. No password/hash/email/session, role, account activation, multi-product merge or OAuth/login handler has been added. The local staging bootstrap still refuses readiness with `/readyz=503`.

**Further gates before identity activation:** separate independent reviewer enrollment/key rotation and revocation, verified ownership evidence and backup, approved accounts/credentials storage, revocation consistency, rate limiting, and real staging e2e migration/rollback. The review code is *not* wired into any runtime endpoint or external automation.

## P0.2 offline, one-time disabled credential staging

The `pendingaccounts.StageDisabledCredential` method is an **offline-only, one-time** credential-provisioning primitive. The caller must already hold a `NewReviewStore` configured with two independent trusted review public keys, and the target subject must already be in `ownership-reviewed` with recorded review metadata. The method hashes a *fresh candidate password* with the standalone Python-compatible Argon2id package, then performs one majority-acknowledged conditional MongoDB update on that same record. The only resulting state is **`credential-staged-disabled`**; it sets `credentials_disabled=true`, `credential_version=1` and `session_version=1` as initialization markers. There is **no active account state**, login API, credential-read API, account migration, or session creation. A replay or competing provisioning request cannot overwrite the hash.

Provisioning a new password does not prove the account holder controls it. Future enrollment must add a validated claimant-facing ceremony and separate operator authorization before enabling this offline primitive for users. Do not use it to copy real credentials or to set a password without account-holder authorization. The existing legacy bcrypt/Argon2 hashes are **not copied** by this operation. Credential change/reset, session-version checking, multi-collection revocation semantics and rollback must be designed and tested before enabling any account. The staging HTTP bootstrap remains unpublished and `/readyz=503`.

Tests use synthetic passwords against an ephemeral MongoDB 7 to verify pending/reviewed separation, exact UUID binding, Argon2id only, disabled state, rejection of unauthorized stores and duplicate/concurrent writes. No production or staging credentials or database connections are used.

### Corrective delivery note: staging credential files

The previous PR #299 merged documentation but **did not land the intended Go source or tests**. This corrective PR adds the actual `pendingaccounts/credential.go` implementation and Mongo integration tests. It **requires the existing short-lived, dual-signed ownership attestation** matching the previously reviewed account; a review store without matching proof cannot set a credential. This distinction matters: simply holding two *public* keys is not proof of reviewer authorization. The operation is still offline-only, still one-time, and still leaves `credential-staged-disabled` and `credentials_disabled=true`; there is no login/authentication API.

The initial session and credential version numbers are metadata only; **they do not yet revoke or check active sessions**, because no active Identity sessions or accounts are enabled. Never expose this primitive in the HTTP bootstrap or provision real users until the claimant ceremony, independent review authority and revocation semantics have been fully reviewed.
