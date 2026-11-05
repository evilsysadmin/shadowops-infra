# Identity staging operational handoff

The executable/image is delivered by [#324](https://github.com/evilsysadmin/shadowops-infra/pull/324).
This handoff defines a separate `shadowops-identity-staging` project, a persistent
Mongo replica, narrowly scoped service credentials, private TLS and a dedicated
Cloudflare tunnel. It does not activate Chronicles or claim a public login.

The staging operator bundle is generated once in Actions and retained as
`identity-staging-operator-bundle` in OCI Vault. It has independent Mongo root
and application credentials, replica key, private CA, service certificate,
JWT signing seed, Chronicles service credential and backup encryption key.
Retries preserve account/signing/backup material; an unreadable or invalid
existing Vault entry fails rather than generating replacement keys. Tunnel
credential rotation updates only that field. No values appear in logs/artifacts.
The Vault bundle must never be mounted whole in either service.

The runtime receives only its app Mongo URI, public Mongo CA, web TLS keypair,
JWT signing seed and the registered Chronicles credential. Mongo receives only
its replica/TLS files. Cloudflared receives its own token and public CA; its
origin uses HTTPS with a pinned hostname and CA, never `noTLSVerify`.
[Cloudflare origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/)
document this trust configuration. DNS refuses to replace an existing foreign target.

Mongo publishes no host port. The app/Mongo and app/tunnel networks are internal;
only the connector has egress. The database volume is dedicated to staging and
is never deleted by the release helper. Fixed root-owned policy accepts only
an immutable Identity image digest, source SHA and Vault ID, checks project
ownership including stopped containers and refuses foreign volumes/networks.
It neither stacks another Compose file nor modifies a product project.

The first operator installation remains explicit. The reviewed installer and
SSH entry point install only the fixed wrapper/policy and a sudo rule granting
`ocarun` that argument-validating staging wrapper. No shell, Docker command,
Docker-group membership or unrestricted sudo is granted. If a reviewed ephemeral Actions
bootstrap is used instead, first establish the actual existing host authority;
working OCI API credentials do not themselves grant root inside the VM. Never
abuse a Chronicles/Chess-only wrapper to install Identity.

`host/bootstrap-identity-staging-over-ssh.sh` resolves protected Infra main and
rechecks it on the adopted A1. It installs `/usr/local/sbin/shadowops-identity-staging`,
its private directories and the isolated policy. Operator-only deployment accepts:

```
sudo /usr/local/sbin/shadowops-identity-staging deploy sha256:<manifest-digest> <40-char-source-SHA> <Vault-OCID>
```

Before calling that command, independently verify the image's build provenance
against `identity-service.yml`, protected-main ancestry and the exact source SHA.
The manual Actions deploy first verifies the exact source checks, protected-main
ancestry, arm64 manifest and build attestation, then invokes only the installed
Identity wrapper through OCI Run Command. It logs only a sanitized
startup receipt; its local state explicitly says `public_login_verified=false`.
OCI may report exit zero while omitting command text. That case records only
`COMMAND_COMPLETED`, never `SERVICE_STARTED`; the separate mandatory HTTPS
readiness and exact source-SHA checks must still pass for the release job to
succeed. Missing/failed exit status and nonempty mismatched receipts remain denied.
The Mongo bootstrap initializes only an empty replica through the localhost
exception; retries authenticate existing users and cannot reset live passwords.
An incorrect root or application password stops the deployment.

The disposable image/Mongo test proves actual TLS signup/login/token/freshness,
logout revocation, startup with the exact runtime role, wrong-password retry
rejection and account persistence after restarting Mongo. It uses an isolated
internal Docker network and publishes no port. Fixtures and all volumes are
removed afterwards; nothing is uploaded or copied into a real environment.

Before consumer activation, complete and record backup/restore (including
preventing restored sessions/credentials from reviving revoked access), certificate
rotation/expiry monitoring, deployment provenance, the reserved `shadowops:`
legacy-namespace preflight, actual Chronicles login/save/reload/logout and a
consumer rollback. Native flags remain off until those gates pass. Production,
legacy account linking, Chess and CKA are outside this first pilot activation.


## One-use authority receipt, 2026-10-30

The user requested an ephemeral Infra workflow using the existing Actions
secrets. [Run 41093882304](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41093882304)
successfully authenticated to OCI and returned only:

```
IDENTITY_STAGING_AUTHORITY docker=no identity_wrapper=no repo=yes operator_sudo=no
```

This verifies that the current agent can observe the A1 but cannot perform the
first Identity installation. No permission was granted or root command executed.
The credential-backed one-use workflow is retired by this handoff; the source
and output-validation tests remain for audit. A first authorized operator must
install the reviewed fixed wrapper/sudo rule before Actions can deploy Identity.
The existing `/opt/shadowops-infra` checkout is present. Never use another
product's wrapper or alter its scope to get around this missing installation.

## Administrative data in staging backups

Snapshot schema 2 includes `admin_inventory_audit` and `staging_application_access_history` alongside the existing account and session collections. Encryption and bounded snapshot limits still apply. Quarantine restore requires all five destination collections to be empty, restores the audit and access summaries, and continues to discard sessions and application tokens disable restored account credentials and reset platform roles to `user`; administrative access requires a separate approved grant. The reader accepts legacy schema 1 snapshots; these cannot supply administrative data that was never captured, and the five-collection empty-destination guard still applies. Never treat restoring a legacy snapshot as recovery of missing audit or access history.

This source change does not activate the admin panel or provision its operators, Mongo roles, credentials or retention policy. Install and verify the reviewed backup code and test backup/restore with disposable data before enabling production of administrative records in staging.

## Opt-in staging administrative inventory

The optional `admin_inventory=enable` provisioning input preserves existing Identity custody and adds one independent Mongo credential. It does not grant an Identity administrator role to any account. The reviewed host wrapper provisions the fixed inventory principal, audit collection and access-summary collection only after verifying an authenticated schema 2 backup less than 24 hours old. The runtime receives the separate inventory URI and enables access summaries; ordinary product credentials and accounts are not replaced.

Before dispatching the opt-in or deploying, install the reviewed updated host wrapper and backup library through the existing operator SSH installation path, run and verify a schema 2 backup, and establish audit and access-summary retention/deletion policy. Confirm the staging administrator's immutable subject and use the separately reviewed role-grant ceremony; product admin privileges and matching usernames do not grant Identity administration. Test the resulting login, audit, access summary and rollback in staging. The opt-in does not backfill old access data.

Normal release retries preserve the admin credential. An existing inventory user with a different password or unexpected role, an unsafe collection or a TTL index on the audit/summary collection stops the release without replacing credentials. The wrapper refuses a legacy configuration after an inventory user exists: disabling requires a separately reviewed procedure that revokes that user before changing privileges. No user, secret, backup or production deployment is changed merely by merging this code.

## Manual Atlas canary and disposable account journey

After installing the reviewed current operator wrapper, Python modules and
sudo policy via `host/bootstrap-identity-staging-over-ssh.sh`, the protected
`identity-staging-operations.yml` workflow accepts two explicit staging actions:

- `atlas-canary`: start the admitted service on a temporary loopback-only port,
  check TLS/readiness/admin page and reject anonymous inventory access.
- `atlas-journey`: perform those checks, then register and log in as a random
  disposable account, verify ordinary-user denial, temporarily grant that
  account admin, verify inventory access, and remove its account and sessions.
  Its audit entry is retained. This is an explicit staging database mutation;
  it does not test the signed role-grant ceremony or grant a real user admin.

Both require `source_sha` naming a protected-main commit with a published,
attested Identity image and successful admission checks. Use that image SHA,
which can differ from the latest workflow-only Infra commit. Both run through
the fixed root wrapper under the existing host-operation concurrency group and
host lock. An authenticated Atlas schema 2 backup less than 24 hours old and a
successful connection preflight are mandatory. Missing wrappers, denied sudo,
failed cleanup, missing output or mismatched source/digest receipts fail the job.
No public traffic is switched. The expected receipts are respectively
`IDENTITY_ATLAS_LOOPBACK_CANARY_OK` and `IDENTITY_ATLAS_ADMIN_CANARY_OK`, each
including the admitted source SHA and digest. Do not count unit tests or a
backup job as evidence that either canary has run against Atlas.

If registration has an ambiguous outcome, the helper reports
`IDENTITY_ATLAS_CANARY_REGISTRATION_UNCERTAIN name=identitycanary_<random>` in
its host stderr. A confirmed account whose cleanup fails reports
`IDENTITY_ATLAS_CANARY_CLEANUP_REQUIRED` with that generated name. Actions
intentionally does not relay raw host output; an authorized host operator must
inspect that diagnostic privately when the fixed canary receipt is missing.
Do not retry blindly or delete by prefix. Review the exact generated account,
its creation time and immutable subject against the failed run, disable only
that verified disposable account, remove its sessions and account, and retain
the audit. If ownership cannot be established, stop for investigation. A
successful later run does not prove an earlier residual account was removed.
A live restore rehearsal and consumer acceptance are still required before
Atlas cutover.
