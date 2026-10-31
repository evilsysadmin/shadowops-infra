# Chronicles central Identity staging activation

Identity is running separately at `id-staging.shadowops.dpdns.org`; production
and the legacy Chess provider remain independent. This change prepares the
consumer release and does not enable it on merge.

The first Identity bootstrap installed only its runtime wrapper. The consumer
needs the reviewed Chronicles wrapper update, and the pilot backup mechanism
needs its own fixed command. Install both once from a clean root-owned protected
Infra checkout on the A1:

```
cd /opt/shadowops-infra
sudo git fetch origin main
sha="$(sudo git rev-parse origin/main)"
sudo git checkout --detach "$sha"
sudo bash host/install-shared-identity-staging.sh "$sha"
```

The final marker is `SHADOWOPS_SHARED_IDENTITY_STAGING_WRAPPERS_INSTALLED`.
This installs policy, bounded snapshot tooling and a daily timer. It does not
restart containers, copy credentials to a product or enable a login. The OCI
agent gains only the fixed `backup <Vault-ID>` command; restore is not delegated.
The Chronicles helper remains the same fixed API deployer, with staging-only
consumer opt-in and explicit rejection of a production service credential.

Release sequence, owned by Infra Actions:

1. `identity-staging-operations.yml`, action `backup`. The root mechanism reads
   the independent Vault bundle, takes a Mongo snapshot transaction, encrypts
   it using the independent backup key and verifies decryption before writing
   root-only ciphertext and a fresh root-owned receipt. Plaintext never leaves
   the host or appears in command arguments/logs/artifacts. The daily timer is
   then configured through that first successful backup.
2. `chronicles-api-staging.yml`, action `provision`, environment `staging`,
   `central_identity=enable`. It copies only the existing Chronicles `soc1_`
   proof into the product's own Vault bundle. It never copies IdP signing,
   database-root, CA-private or backup keys. Ordinary reprovisioning preserves
   the opted-in credential; `central_identity=disable` removes it for rollback.
3. Deploy the signed current Chronicles API source through its owner workflow.
   The host refuses native activation without a recent valid Identity backup
   receipt. The API's own read-only reserved-namespace preflight must also pass
   before routes are wired. Namespace conflicts require explicit review rather
   than account adoption. Confirm actual central login, profile, save/reload,
   refresh, logout/revocation and legacy compatibility before the frontend.
4. Set Infra variable `CHRONICLES_CENTRAL_IDENTITY_STAGING=enabled` and manually
   dispatch `chronicles-pages-release.yml` for staging with `only_if_new=false`.
   This forces an owned rebuild even if the same source SHA already has a
   Pages receipt. The value is a public feature flag, never a credential.
   The production build has no corresponding opt-in. Verify the actual browser
   journey at the public staging game after publication.

Rollback: disable the frontend variable and force a staging rebuild; provision
with `central_identity=disable` and redeploy the admitted API. Profiles, UUID
bindings and saved games are preserved. Keep the reserved namespace protected.
Do not link old usernames or transfer admin rights during this pilot.

## Staging-only Chronicles admin grant (separate, reviewed operation)

Central Identity JWTs prove the immutable account subject, **not** game roles.
The legacy `evilsysadmin` username is not the same identity as
`shadowops:staging:<UUIDv4>`. Never infer equivalence by display name or
automatically transfer privileges during the pilot.

A scoped admin grant requires all of the following **before enabling**:

1. An operator independently reviews ownership of the exact central account
   using trusted Identity account records and an authenticated ownership
   process. A screenshot of `/auth/me` is a diagnosis, not authorization.
   Record a private approval/audit reference; do not put a real subject UUID
   in GitHub PRs, issues, logs or public action inputs.
2. Store the canonical **full profile key** `shadowops:staging:<lowercase UUIDv4>`
   in the protected **staging GitHub Environment secret**
   `CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE`. This is product-specific;
   no aliases, CSV, wildcard, legacy username, unsigned client-side flag,
   production identity or non-v4 UUID is permitted.
3. The new root-owned `host/chronicles-api-deploy.py` policy must be installed
   through the existing reviewed host bootstrap. Older installed wrappers
   intentionally reject the new Vault bundle key.
   The grant-enabled provision workflow **also checks the installed wrapper**
   non-privileged via OCI, compares its exact hash to the protected Infra
   checkout and rechecks Infra main before allowing any Cloudflare/Vault
   mutation. An absent, unsafe, outdated wrapper, untrusted probe result or
   superseded main **fails closed**. This automatic guard runs only for
   `staging` + `central_admin=enable`; normal provisioning and production
   are unaffected. A manual read-only `oci-host-probe.yml` run remains
   available as an earlier diagnostic.
4. **Preferred one-dispatch operation:** in `chronicles-api-staging.yml`
   choose `action=grant-admin`, `environment=staging`,
   `central_identity=preserve` (or `enable` only after the usual
   Identity backup prerequisites). Select `main` and leave `source_sha`
   empty to use the admitted, current Chronicles source. This action
   **overrides** `central_admin` to `enable` and ignores `only_if_new`,
   so the granted profile is copied only to the private Chronicles Vault
   bundle and the already-signed Chronicles API is **re-deployed even for
   an unchanged source SHA**. Provision must succeed before image admission;
   a failed preflight/secret, unsupported environment or failed provision
   **cannot start deploy**. The same root-owned wrapper check, protected
   environment, source CI, image attestation, OCI freshness and public
   staging smoke apply as in the independent operations. Production is
   not an allowed grant target.
5. If needed for recovery or rollback, the original two-dispatch sequence
   still works: `action=provision`, `environment=staging`,
   `central_admin=enable`, then `action=deploy`. The one-dispatch action
   is an operator convenience, **not** permission to skip the independent
   identity-ownership approval or protected secret in steps 1 and 2.
6. After the deployment finishes, verify with a **real newly authenticated**
   central session that `/api/auth/me` returns `isAdmin:true` for the
   approved profile only; verify the `/api/chronicles/admin/users` census
   endpoint for the owner and an unrelated account (403), and confirm
   the in-game panel. The job's existing public smoke does not authenticate
   as the private admin, so it is **not proof** that the grant is active.
   Check the exact running image SHA and runtime before closing the incident.

The one-dispatch run **fails visibly** if the Chronicles source SHA is
superseded between admission and OCI deploy; automated deploys continue
to skip obsolete generations. If provisioning succeeds but admission or
deploy fails, the reviewed Vault configuration may be staged without a
successful rollout: retry the controlled `action=deploy` (after
verifying the current source), or explicitly revoke via
`action=provision` + `central_admin=disable` and redeploy. Never
declare the role active on the strength of a successful Vault write alone.

The default `central_admin=preserve` retains an **already reviewed** grant
across ordinary reprovisioning. `central_admin=disable` removes it from the
new Vault bundle; disable Central Identity itself also removes the runtime
grant. Production never accepts this profile-key grant. A missing/invalid
secret or inactive central consumer must cause the enable operation to fail
without changing permissions. Rollback is explicit revoke/redeploy, not
a client-side concealment.

See Chronicles issue #1029. Until this reviewed operator step and a verified
staging deployment, the user's administration is **not restored**.

## Snapshot/restore contract

Pilot snapshots are bounded to 16 MiB and 10,000 rows per collection, encrypted
with authenticated Fernet under the separately generated Vault key. Files are
root-only under `/var/lib/shadowops/identity-staging/backups`; restore tests use
only fresh disposable Mongo instances. These are on-host pilot snapshots; an
off-host disaster-recovery copy is still required before production use.

An operator-only restore accepts an authenticated staging snapshot only with the
Identity app stopped and an empty destination. It retains UUIDs and account data,
but clears sessions/token registrations, increments session/credential versions,
removes password/recovery proofs and quarantines accounts as `restore-review`.
A separate ownership review and fresh credentials are required to reactivate
accounts. It never overwrites populated collections or revives revoked access.
The real image/TLS Mongo test snapshots an active session, revokes it, rejects a
nonempty restore, restores into the empty fixture and proves the original
password, cookie and freshness proof are denied after restart.

Origin certificates are independent of JWT keys and have a 90-day validity.
The existing native healthcheck validates their dates; renew before expiry with
the staging private CA and preserve database/signing/consumer/backup credentials.
Changing certificates requires an operator-controlled service restart and fresh
readiness/source checks. Production keys, backups and certificates remain separate.
