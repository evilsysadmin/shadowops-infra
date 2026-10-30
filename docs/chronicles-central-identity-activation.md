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
