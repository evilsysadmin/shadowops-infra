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

## P0.2 version-bound session validation (read-only, staging-only Mongo guard)

`session.VersionedValidator` is an additional **strict, read-only** validator, not a login or session issuer. It rejects unversioned handles and requires `Record.SessionVersion > 0` to equal the current `pending_accounts.session_version` on every check. The staging `pendingaccounts.VersionGuard` uses a **primary, majority-read** MongoDB query that requires exactly `state=active` and `credentials_disabled=false`. Current production code **cannot activate a pending account**; only ephemeral Mongo integration tests insert a synthetic active record for validation coverage. The previous storage-only `Manager.Validate` and `Manager.Rotate` explicitly refuse versioned handles so they cannot bypass this guard.

The Mongo `sessions` collection now stores an immutable `session_version`; the conditional refresh `Swap` additionally matches that stored version and cannot upgrade it. Tests cover disabled/missing accounts, mismatch after a synthetic atomic account-version increment, refusal of a forged version upgrade, stale/zero versions, invalid environment, malformed account data and failure of the account reader. There is no cache. **Limits:** this is NOT full linearizable cross-collection revocation: concurrent account changes and authorization decisions still need an explicit transactional/ordering contract before a real login or refresh path can be enabled. There is no account activation, credential reset/rotation API, or live session validation endpoint in this PR. Bootstrap stays `/readyz=503`. No real account is read or modified.

## P0.2 transactional suspension + revocation (offline-only)

`revocation.NewStagingRevoker` is **not an authenticated API**: the caller must independently prove it has permission to administratively suspend the account; the library has no user-facing transport. Its only operation `SuspendAndRevoke(ctx, immutableUUID, expectedSessionVersion)` acts on **staging only**. In a **single MongoDB replica-set transaction** with snapshot reads, primary routing, and majority commit, it matches the active account at its exact expected version, changes it to `credential-staged-disabled`, sets `credentials_disabled=true`, increments `session_version` once, and deletes all of that subject's staging session records. If the session deletion fails, **neither the version bump nor disabling may commit**; repeated or competing requests cannot both succeed. No password reset or new credentials are introduced.

A standalone MongoDB server **cannot** run this transaction. CI adds a separate, disposable single-node **Mongo 7 replica set** bound to `127.0.0.1:27018`, with tests for committed revocation, isolated other subjects, forced rollback, wrong expected version, cancellation and concurrent suspension. The existing standard Mongo CI and its independent jobs remain unchanged. No production databases, live accounts, cookies or secrets are involved.

**Still pending before any real auth rollout:** proper authorization of the administrative caller, a version-bound *issuance* protocol, active login/logout/refresh flows, credential rotation/recovery workflow, replay/CSRF/rate limits, continuity under network partitions and read-ordering tests. The read-side VersionedValidator uses primary/majority reads but cannot promise perfect linearizability for an authorization decision racing the exact commit instant. No endpoint invokes this primitive. The bootstrap remains `/readyz=503`.

## P0.2 transactional, credential-bound staging issuance (offline integration only)

`issuance.NewStagingIssuer` is an **unwired Go library** for staging-only synthetic tests. It only accepts an immutable UUIDv4, checks the existing active account is enabled, verifies an Argon2id/bcrypt password against a bounded KDF **before** starting a transaction, and reads `credential_version` and `session_version`. Within a MongoDB replica-set transaction, it conditionally matches **both versions and the exact credential hash**, increments a non-permission `login_fence` on the *same account document modified by administrative suspension*, then inserts an opaque version-bound session in the sessions collection. Session digests, not raw handles, are persisted. Only after a majority-committed transaction is the 256-bit random handle returned.

This real account write is critical: it prevents a transaction that read an active account before suspension from inserting a fresh session *after* the suspension transaction committed. Transaction write conflicts retry with the same credential/version preconditions and fail closed if they no longer match. There is still no active-account provisioning API and no HTTP endpoint, cookie, CORS, rate limiter, or public login. Tests synthesize `active` accounts **only in disposable MongoDB replica sets**; production and staging operational databases are untouched.

**Not a deploy approval:** passwords must not be offered to this offline library by untrusted remote callers before account claimant enrollment, abuse controls, CSRF and per-consumer authorization are audited. In-flight validation decisions racing revocation are not guaranteed globally linearizable merely by majority reads. `/readyz` remains 503.
## P0.2 staging-only, version-fenced session refresh (offline)

`issuance.Issuer.Refresh(ctx, oldHandle)` rotates a previously issued **version-bound**, opaque staging session once; it is deliberately **not** a public refresh endpoint. It rejects malformed/legacy handles and expired sessions. The new 256-bit handle is stored as an environment-bound digest, the original handle is invalidated by Mongo `Swap`, and the session's absolute 24-hour expiration, subject and version never change.

The refresh transaction uses snapshot reads and majority commit, conditionally updates the **same active account document** fenced by `SuspendAndRevoke`, and CAS-swaps the original session **in the same transaction**. Replay, conflicting refresh, revocation, disabled accounts, and account-version changes fail closed; the caller receives no new handle without a confirmed commit. MongoDB replica-set tests cover replay, strict versioning, unchanged expiry, deliberate rollback, and simultaneous refresh/suspension. This does **not** make in-flight authorization reads globally linearizable.

No live accounts, secrets, HTTP login/refresh/logout, cookies, tokens, rate limiting, production DB or deploy wiring are enabled. The loopback-only bootstrap continues to return `/readyz=503`. Operational account activation and human/administrator authorization must be independently reviewed before this code can process real sessions.

## P0.2 offline administrative suspension approval contract (not wired)

`revocation.ApprovalVerifier` is a pure cryptographic **precondition design**, not an admin API or a permission grant. It accepts **exactly** the `suspend-and-revoke` action on one staging UUID, binds the exact expected `session_version`, a canonical Infra review issue reference, a lowercase SHA-256 evidence digest, a 128-bit nonce and a five-minute approval window. An operator and a separately pinned security reviewer must each sign the **same domain-separated canonical JSON** using distinct Ed25519 keys in fixed roles. Keys are provisioned independently, never accepted from user input, and the operator must check that these belong to genuinely independent authorities. A GitHub issue or signature alone does **not** prove the underlying human review happened.

The verifier rejects production, wrong actions/subjects/versions/tickets, malformed evidence/nonces, expired or prematurely valid approvals, wrong/reused keys, swapped signers and missing signatures. It is intentionally **not connected** to `SuspendAndRevoke` or any deployed runtime. Verification by itself cannot prevent replay: a future PR must atomically consume the nonce in a dedicated, durable, audit-preserving Mongo journal **in the same transaction as** account suspension and session deletion, and must enforce an operator lifecycle, independent key rotation/revocation and permission model. Do not expose a network endpoint or treat a valid approval as sufficient authorization until those gates are audited. All tests use synthetic keys and subjects, and `/readyz` remains 503.

## P0.2 transactional single-use administrative suspension journal (offline-only)

`revocation.NewAuthorizedStagingRevoker(ctx, client, operatorKey, securityKey)` is an **explicitly separate staging-only** library constructor requiring two distinct, externally pinned Ed25519 public keys and the dedicated `shadowops_identity_staging` Mongo client. Constructor **only verifies** a separately preprovisioned, unique and non-TTL `(environment,action,nonce)` index; it never creates indexes or collections. The `admin_suspension_journal` is persistent and intentionally has **no TTL**: signed approval expiry must never erase its replay history. Index creation or other journal failures fail closed.

`SuspendAndRevokeApproved(ctx, signed)` rechecks the previously defined two-signature approval both before and within each Mongo transaction attempt. In **one snapshot transaction with majority commit**, it conditionally suspends the exact active staging account at the signed expected session version, deletes that subject's sessions, then inserts a nonce-keyed, append-only audit event. An invalid, duplicate, expired or reused nonce (including on a different account), a conflicting session version, failed delete, failed journal write, or interrupted transaction **commits none** of those changes. Audit data includes the immutable UUID, review issue, evidence and approval SHA-256, signer public-key SHA-256 fingerprints, version and timestamps; no private evidence, passwords or raw signatures. A successful operation only returns after majority commit; tests use a disposable MongoDB 7 replica set to prove replay, cross-account nonce collision, rollback and concurrent requests.

**Important trust boundary:** This library is **not** a publicly accessible or production-ready authorized administrator workflow. The prior `SuspendAndRevoke` offline primitive still exists for backwards-compatible internal tests and is **not** gated by the signed verifier; never route it to an HTTP, job or operator API. The new entry point additionally requires independent human reviewer authorization, signing-key enrollment/rotation/revocation, controlled Mongo permissions, audit retention/backups and operational rollback validation before use with real accounts. Cryptographic signatures cannot establish the quality or independence of the underlying human review, and snapshot/majority semantics do not promise globally linearizable in-flight reads. No account activation method, live HTTP route, cookie, production data, OCI/Cloudflare deployment or consumer SSO is enabled; bootstrap `/readyz=503`.

## P0.2 fail-closed key-policy generation fence (offline only)

Administrative approval signatures now bind `policy_generation` (strict positive integer) in the domain-separated signed message. The separate `AuthorizedStagingRevoker` will **fail closed** unless a preexisting dedicated staging Mongo document in `admin_signer_policy` matches `_id=staging:suspend-and-revoke`, `environment=staging`, `action=suspend-and-revoke`, `state=active`, the exact signed generation, both separately pinned operator/security Ed25519 public-key SHA-256 fingerprints, and validity bounds `not_before` / `not_after`. The key policy must already be active when the approval is signed and remain active through execution. **No runtime or administrative API provisions this document.** CI creates synthetic policy fixtures in its ephemeral replica set only.

Each approved suspension transaction makes a **real conditional write** to that signer policy document (`use_fence` increment) *before* changing the account and sessions and inserting its audit entry. This creates a MongoDB write conflict with a concurrent operator-key retirement/rotation update to the same document, rather than accepting a stale in-memory snapshot. Rotating the pinned fingerprints and incrementing `generation` invalidates both cached old-process keys and old approvals; even re-enrolling identical keys with a new generation cannot validate an earlier signed operation. Retiring/revoking a policy, an absent/malformed policy, or a policy outside its validity window causes denial without a session or account mutation. Failure of any transaction step also rolls back the key-policy fence.

**Boundary:** this PR does not implement a trusted key enrollment/rotation/revocation command, immutable or signed policy history, independent authority attestation, operator RBAC, DB privileges, backups or recovery. An entity capable of arbitrarily overwriting the MongoDB signer-policy document still controls this boundary. No real credentials, users, HTTP admin route, OCI staging or production deployment are enabled. The legacy offline ungated `SuspendAndRevoke` remains separate and MUST NOT be wired to users. Bootstrap `/readyz=503` remains unchanged.

## P0.2 independent dual-approved emergency signer retirement (offline only)

`revocation.NewStagingPolicyRetirer` is a narrow **staging-only, offline emergency kill switch** for the existing `admin_signer_policy` document. It pins **two distinct governance Ed25519 public keys** provided out of band; these MUST be independently administered and MUST NOT be the same keys as either operational signer. This library does not create or enroll governance keys, sign statements, or expose HTTP/CLI access.

A `RetirementStatement` signs exactly the staging `retire-signer-policy` action, the currently active key policy `generation`, exact operator/security signing-key SHA-256 fingerprints, review issue, evidence SHA-256, a 128-bit nonce, and a maximum five-minute expiry. Each approval needs **both** governance signatures in designated roles. The statement is domain-separated from regular administrative suspension approvals; swapped roles, stale signatures and alterations fail closed. Merely providing signatures does not verify that two distinct humans examined authentic evidence.

`StagingPolicyRetirer.Retire` checks signatures again on every transaction retry, then in **one snapshot/majority Mongo replica-set transaction** conditionally matches the exact active signer-policy generation/fingerprints, sets `state=revoked`, increments `generation`, and appends an immutable-intended, unique-nonce audit event in `admin_signer_policy_events` (no TTL). The write hits the **same signer-policy document** updated by `AuthorizedStagingRevoker` during signed account suspensions. Transactions therefore conflict rather than letting cached signers bypass a completed retirement. Audit failures, conflicts and interrupted operations roll back every change; no partial state or reusable nonce leak is accepted as success. Integration tests use a disposable MongoDB replica set and synthetic signing keys, never actual operators or databases.

**Not a live operator management system:** independently securing/enrolling/revoking the governance keys, proving authorization of the human signers, immutable/writable-only journal privileges, secured Mongo credentials, offsite audit backups, trusted bootstrap, rotation/re-enrollment and recovery procedures, and actual consumer staging E2E tests remain mandatory. This is a one-way **emergency retirement**, NOT rotation/re-activation. The legacy ungated offline `SuspendAndRevoke` remains untouched and MUST NEVER be exposed as an administrative endpoint. No real Identity login, production data, OCI/Cloudflare deployment or token paths are changed. The local bootstrap remains `/readyz=503`.

## P0.2 audited recovery after emergency signer revocation (offline only)

`revocation.NewStagingPolicyRecoverer` adds a **strictly post-retirement** recovery primitive. There is still **no initial account or signer trust bootstrap** and no public API or operator CLI. It uses the two *independently pinned* governance Ed25519 public keys already required by the emergency retirement code. Recovery accepts only a `revoked` `staging:suspend-and-revoke` policy, matching **the exact post-retirement generation and the previous operator/security SHA-256 public-key fingerprints**. The transaction must also find the committed retirement journal event for the previous generation and match its `executed_at` to the policy's `revoked_at`; manually inserting a bare `revoked` policy is insufficient.

`RecoveryStatement` binds one action (`recover-revoked-signers`), one staging environment, the retired generation/fingerprints, the exact two new Ed25519 public keys (canonical lower-case hex), a bounded **new operating window (maximum 30 days)**, review issue, evidence SHA-256, nonce and a **five-minute authorization window**. It requires **four Ed25519 signatures over the SAME, domain-separated canonical message**: both independent governance signers approve the action and both new operational signers prove possession of their respective private keys. New keys must be distinct from each other, from both retired operator/security keys (including cross-role reuse) and from both governance keys. Pinned governance keys also must not equal the retired operational pair. A signature alone does not establish that the signer's human identity or review evidence is trustworthy.

The recoverer updates the **same policy document** and appends an event to the **same durable unique-nonce, no-TTL** `admin_signer_policy_events` journal, **atomically in one snapshot/majority Mongo transaction**. It promotes `revoked → active`, increments the generation again, installs only the new signer-key fingerprints, sets the precise operational `not_before/not_after` window and removes `revoked_at`. It stores no raw signatures or secret material. All prior approvals remain invalidated by generation/fingerprint checks; old signer processes remain denied by the existing transactional `use_fence` guard. Neither suspensions nor existing account/session records are modified during signer recovery. Invalid signatures, missing predecessor audit, replay, failed journal insert and transaction rollback fail closed.

**Operational limits:** the code contains no authority enrollment or external attestation, secure signing CLI, MongoDB role setup, audit backups, initial bootstrap, production keys or user-facing routes. Untrusted database write privileges, governance-key compromise or tampering with immutable-intended audit history remain outside the offline library's guarantees. Recovery is deliberately *not* possible from an active policy or an unaudited/missing policy. Staging bootstrap `/readyz=503` and all production resources are unchanged.

## P0.2 one-time offline staging administrative signer bootstrap (NOT live)

`revocation.NewStagingSignerBootstrapper` creates the very first `staging:suspend-and-revoke` signer-policy document with **generation 1**, but only under a separately trusted offline ceremony. It takes **two independent, pre-pinned governance Ed25519 public keys** supplied out of band (never from the signing request, Mongo or HTTP). A `BootstrapStatement` fixes staging, exactly `bootstrap-staging-signers`, two canonical Ed25519 operational public keys, a maximum **30-day** operating window, evidence SHA-256, review issue, 128-bit nonce and a **five-minute** approval window. The same domain-separated bytes require **four signatures**: two governance authorities and proof-of-private-key possession by both new operational signers. The four keys must be distinct across the operational pair and the governance/operational boundary. No private keys, signatures or secrets are written to Mongo.

`Bootstrap` inserts **both** the initial policy and a permanent genesis journal record with the deterministic ID `staging:bootstrap-signer-policy` in **one snapshot/majority MongoDB replica-set transaction**. The existing `admin_signer_policy_events` collection retains a non-TTL, unique action/nonce index; the fixed genesis ID also prevents a *different* nonce/signing ceremony from bootstrapping another policy even after accidental deletion of the policy document, **provided the durable journal is not modified or deleted**. An existing active, retired, revoked, partially written or malformed policy is **never** overwritten. Concurrent attempts, duplicates, invalid or stale signatures, lost audit inserts and interrupted transactions fail closed; on abort neither policy nor genesis event is committed. The newly enrolled signers are thereafter subject to the existing signed-generation, live-policy and transaction write fences for account suspension. The retirement/recovery workflow remains distinct.

**Security prerequisite, NOT solved in code:** trusted governance key generation and custody, verified independent human review, secure signing ceremony/device, explicit approval process, least-privilege Mongo database roles, immutable or externally replicated audit history and offsite backups. Any caller permitted to supply fake governance trust anchors or delete *both* policy and audit history can subvert the ceremony. There is **no authenticated operator endpoint**, initial trust bootstrap into a live environment, HTTP, user-account activation, deployment, actual signer keys or OCI/Cloudflare secret configuration in this PR. All integration tests use synthetic Ed25519 keys in a localhost disposable Mongo 7 replica set. Bootstrap readiness stays `/readyz=503` and production remains untouched.

## P0.2 administrative audit indexes: privileged DDL separated from runtime (offline only)

`revocation.PrepareStagingAdministrativeIndexes(ctx, client)` is now the **only** method in the administrative-revocation package that creates the unique `environment,action,nonce` indexes on `shadowops_identity_staging.admin_suspension_journal` and `admin_signer_policy_events`. It is a **separate offline schema-maintenance operation**, not startup logic. Run it with a separately controlled staging schema-owner credential *before* any administrative executor starts; remove that credential from the executor's environment. The maintenance operation is idempotent for matching indexes but will fail closed if any journal has an unsafe TTL index. No live database, credential, role or migration is provisioned by CI.

All four admin operation constructors (`NewAuthorizedStagingRevoker`, `NewStagingPolicyRetirer`, and their derived bootstrap/recovery constructors) now inspect the existing indexes with **listIndexes only**. An absent collection, absent or non-unique index, sparse or partial unique index, or **ANY TTL index on the same journal collection** rejects initialization. They never call `createIndexes`. The fixed genesis and nonce identifiers retain MongoDB's built-in unique `_id` guard. This is a fail-closed **schema prerequisite**, not proof that the audit is immutable. `listIndexes` itself must be explicitly allowed by the eventual narrow runtime roles.

**Operational role separation to enforce when real staging Mongo identities are created:**

| Identity | Allowed actions by collection | Must NOT be granted |
| --- | --- | --- |
| Offline schema maintainer | `createIndex` / `listIndexes` on the two audit journals, and narrowly required collection creation | Any runtime operational key, sessions/accounts mutation, broad `dbOwner`/admin role |
| Signed suspension executor | `update` on `admin_signer_policy` and `pending_accounts`, `remove` on `sessions`, `insert` + `listIndexes` on `admin_suspension_journal` | `update`, `remove`, `dropCollection`, `createIndex`, `collMod` on its audit journal |
| Offline governance retirement/recovery | `update` on `admin_signer_policy`, `insert` + `find` + `listIndexes` on `admin_signer_policy_events` (recovery needs predecessor lookup) | `update`, `remove`, `dropCollection`, `createIndex`, `collMod` on audit journal; account/session writes |
| Offline initial bootstrap | `insert` on `admin_signer_policy`, `insert` + `listIndexes` on `admin_signer_policy_events` | Existing-policy overwrite, journal update/delete, general account/session reads or writes |

These are **intended scopes**, not applied MongoDB RBAC roles: exact grants, role inheritance, transaction permissions, createCollection rules and auth-enabled replica-set tests still require review before deployment. In particular, inherited `readWrite` or `dbOwner` privileges would defeat the append-only evidence guarantee. Use distinct operator identities; MongoDB admins and anybody with permission to remove both an audit journal and its policy can still rewrite history. Back up or replicate journal entries to an independently administered append-only destination, verify restores and alert on `dropIndexes` / `collMod` / `dropCollection` attempts before trusting them.

No real credentials, accounts, IDP HTTP endpoints, deployment or production resources change. Bootstrap remains `/readyz=503`.

## P0.2 authenticated MongoDB 7 audit RBAC probe (CI-only)

The independent `identity-rbac.yml` CI gate uses a **disposable localhost-only MongoDB 7 replica set with authentication and an internal random keyfile**. Random, short-lived passwords are generated during the CI job; none are committed, taken from Cloudflare/OCI, or provisioned in any persistent database. The CI role installer (`rbac/seed.mongosh.js`) grants precisely two custom *staging* roles without inheriting `read`, `readWrite`, `dbOwner` or administrator roles:

- **Index maintainer**: only `createIndex` and `listIndexes` on `admin_suspension_journal` and `admin_signer_policy_events`. The authenticated test verifies both successful index installations and rejection of inserts, account modifications, session deletion and journal updates.
- **Signed suspension executor**: only `insert` + `listIndexes` on `admin_suspension_journal`, `update` on `admin_signer_policy` / `pending_accounts`, and `remove` on `sessions`. The test verifies index inspection and one four-write **snapshot/majority Mongo transaction** (policy fence, account disable/version increment, session deletion and journal append), then checks results using the disposable CI root connection. It requires denial of audit `find`, `update`, `remove`, `drop`, `createIndexes`, `dropIndexes`, `collMod`, governance journal insertion and out-of-scope collections.

This is a **real authenticated Mongo privilege-enforcement regression test**, not a deployment of those roles, not an E2E Go admin command under production credentials, and not a proof against a compromised Mongo administrator. The test root retains broad rights only inside the disposable container. These role definitions are examples for a future controlled operator process; **never copy or execute the CI seed against a real staging or production database without separate review**. Future work must test governance and bootstrap roles, application-level actor separation and real least-privilege Go clients, immutable independent journal export, backup/restore, human operator enrollment and rollout. No actual login is enabled and `/readyz` stays 503.

## P0.2 offline CKA token bridge gated by a versioned staging session

`issuance.NewCKAPoCSigner(issuer, stagingSeed)` combines the **actual MongoDB-backed staging `issuance.Issuer`** and an independently held 32-byte staging Ed25519 seed. It is **not wired to HTTP**; it does not authenticate a login request, register a user, add an operator/role or enable any CKA lab API. No CKA-audience signing operation is exposed by the standalone `core` or runtime handlers.

`CKAPoCSigner.IssuePoCToken(ctx, opaqueSessionHandle)` accepts **only** an existing canonical `so1_` session handle, never a user-supplied UUID or audience. Inside one MongoDB snapshot/majority transaction, it reads the stored staging session digest, checks UUIDv4 subject, positive session version, valid **absolute** session lifetime, and writes the **same account document** used by suspension/revocation under an exact `active`, `credentials_disabled=false`, `staging`, matching-session-version filter. A failed/racing revocation, stale handle or stale session version cannot produce a *new* token; failed account-fence writes roll back, without signing. Only after majority commit does it sign a narrow JWT with issuer `https://id-staging.shadowops.dpdns.org`, audience `cka-simulator`, subject from the verified session, signed `sv` and `jti`, and a maximum **two-minute** validity also capped to the absolute session expiration. `JWKS()` returns public-only Ed25519 material using the same canonical `core.New("staging", seed)` key derivation as the existing CKA PoC consumer; the signing seed is not stored in MongoDB or exported by that method.

**Critical revocation boundary:** revoking an account *after* a JWT has been minted **does not erase its cryptographic validity** until its short expiration. This token is intended only for a **local, explicitly synthetic** interoperability PoC, not access authorization. No public consumer, runner or service may rely on these JWTs alone to grant access. Before live CKA authentication, the consumer or a trusted auth gateway must check current session/account revocation (version or server-side token status) and per-product authorization; also implement session-bound login/logout/refresh, rate limiting, secure cookies, issuer/key rotation, independent secret management, least-privilege Mongo role and audited staging deployment. The existing `runtime.NewStagingHandler` still exposes **only /livez, /readyz=503 and /api/identity/jwks**, with no token or credential HTTP endpoint. The CKA static preview is unchanged.

Ephemeral Mongo 7 integration tests prove valid version-bound synthetic session → publicly verifiable two-minute CKA token, no session mutation, wrong handles denied, invalid seed rejected, refreshed stale handle denied, account-version bump denied, rollback after account write and no new token after account suspension/deletion. Real accounts, production and OCI remain untouched.

## Session-bound token freshness authority (staging, internal)

The CKA PoC signer now commits a token-to-session binding in
`staging_cka_tokens` in the same snapshot/majority transaction as its account
fence. Its `_id` is a domain-separated SHA-256 of the canonical JTI; the record
contains the source session digest, exact subject/version/issuer/audience and
bounded issuance/expiry. No raw JWT, raw JTI, signing key or session handle is
stored. Failed registration means no token is returned. MongoDB's unique `_id`
prevents duplicate registration. Expiration is checked synchronously; TTL
cleanup is not an authorization guarantee. Retention/housekeeping and deployed
least-privilege roles remain operational prerequisites.

`issuance.NewStagingCKAFreshness` constructs an independent checker without a
signing key. `Check(ctx, subject, version, jti)` accepts only a canonical UUIDv4,
positive int64 version and canonical 16-byte JTI. It checks the actual registry,
source session and active account in one snapshot/majority transaction, making
conditional fence writes to all three documents so refresh, session deletion,
token deactivation and account suspension cannot be bypassed by a stale read-only
snapshot. Missing records, malformed bindings, expiration, disabled credentials,
store errors, cancellation and its two-second deadline produce no active
evidence. A concurrent check may order **before** revocation; its evidence is a
point-in-time observation, not a two-second authorization lease.

The evidence fields match CKA's freshness contract: `issuer`, `subject`,
`session_version`, `token_jti`, `checked_at`, `account_active`, `session_active`,
`token_active`. A consumer must first verify JWT signature/issuer/audience/times
and must invoke its trusted checker for every protected operation. This internal
Go authority is **not yet a deployed provider**: no authenticated service
transport, public login/token endpoint or CKA adapter is wired, and `/readyz`
stays 503. Do not replace the missing provider with a browser field or fake
callback, and do not enable lab access. The fixed CKA audience is intentional;
other products need separately validated audience-bound integrations.
