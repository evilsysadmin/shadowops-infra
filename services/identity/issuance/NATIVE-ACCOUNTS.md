# Native staging accounts

`NewStagingNativeAccounts(ctx, issuer)` enrolls **new ShadowOps accounts**.
It uses the isolated staging database and existing version-fenced session,
token and revocation machinery. The temporary shared account collection keeps
its historical `pending_accounts` name; native documents have an explicit
`source=shadowops-identity`. Every native name lookup includes that source.

Registration inserts a fresh random UUIDv4 and Argon2id password hash, with
credential/session versions 1. Names are case-insensitive ASCII identifiers
(3–32 characters, letter first, then letters/digits/underscore); passwords need
at least 15 Unicode code points and at most 4096 UTF-8 bytes. The existing unique
`environment,source,alias_key` index prevents concurrent/case-only duplicates.
No session or product profile is created until the respective login/use.

Registering a name also found in a Chess/Chronicles legacy reservation creates
a different central UUID. It does not activate, rewrite, link, recover or claim
that reservation, its password, saved games or roles. Legacy ownership review
and linking remain separate. Consumers must bind local profiles to verified
issuer+UUID, never assign existing game data through the native login name.

Registration returns a 256-bit random backup code once. Only its domain-separated
SHA-256 digest is stored; no email address or mail service is involved.
`Recover` requires that code, replaces the password, rotates the code, increments
both credential and session versions, and deletes **all** browser sessions in
one snapshot/majority transaction. Source/state/versions/code are rechecked in
the transaction; concurrent/replayed recovery has one winner. A failed commit
returns no code and leaves the old password/code/sessions intact. Account
suspension cannot be undone by recovery. A lost password **and** backup code
requires a separately verified ownership process; no username-based reset exists.

These APIs must sit behind the HTTPS handler's bounded KDF concurrency and
abuse/CSRF controls. The old bootstrap does not instantiate them. Integration
tests exercise native/legacy separation, uniqueness, three-audience and
multi-browser revocation, password/code replay, transaction rollback and
concurrent registration/recovery against disposable MongoDB 7. No real
accounts, deployment, public route or application trust changes in this PR.
