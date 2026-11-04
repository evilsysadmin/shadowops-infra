# Identity staging: handoff for the first platform administrator

Status: design only. No role has been granted and no live role-operation
workflow has been installed. This document does not authorize use of backup
custody credentials or creation of a superuser workflow.

## Goal

Allow one verified ShadowOps Identity staging subject to receive the platform
`admin` role through the existing `services/identity/roles` contracts. The
account name alone is not the target: bind a verified immutable subject and
its current role and session version. The transaction also revokes existing
browser sessions and application tokens, so the subject must sign in again.

## Existing contracts and prerequisites

* `PrepareStagingRoleJournalIndex` requires a separately provisioned schema
  maintainer principal. It verifies the unique, non-TTL audit index.
* `StagingRoleBootstrapper` requires its own narrowly scoped Mongo principal,
  two pre-pinned governance public keys and four signatures: two governance
  signatures and proofs from two different operational signers. It inserts
  the one-time policy genesis and audit event atomically.
* `StagingRoleExecutor` requires a different Mongo principal, the pinned
  operational public keys and a short-lived role-change request signed by
  both operational signers. It checks policy, target and session version in
  an atomic audited transaction.
* Public keys, issuer identities and evidence of control of the target subject
  must be independently verified before use. A GitHub username or the user
  entering a login name is not proof of subject ownership.
* The existing encrypted backup does not include the role policy and role
  journal. An explicit recovery and anti-replay design for those records is
  required before enabling the workflow.

## Workflow design to implement once its trust roots exist

Use a manual-dispatch workflow restricted to protected `main`, with three
separate operations and identities: journal schema, one-time signer genesis,
and one signed role change. Each operation must use its own narrowly scoped
principal; the public Identity service and backup custody credentials must
never be used. The exact, reviewed source SHA and workflow inputs must be
bound to the execution. Keep private signing keys outside the workflow. Do not
put account identifiers, signatures, Mongo URIs or credentials in dispatch
inputs or logs. The signed request needs a protected, short-lived handoff;
the existing five-minute validity window includes queueing and environment
approval. An expired request must fail closed and require new signatures.

Run only on an isolated, ephemeral runner with authenticated network access
to the staging database, TLS verification, no untrusted jobs, and teardown
afterwards. The GitHub repository currently has no registered self-hosted
runner (checked 2026-11-04); the ordinary hosted runner has no established
private database path. A runner label or a secret name alone does not create
that access. Pin the independent public trust roots outside the signed
request and protect their modification separately from workflow dispatch.
The CLI adapter must expose only the existing fixed staging operations, reject
unknown fields and expired or malformed requests, avoid logging request or
connection contents, and fail closed on database, signature or policy errors.
Tests must exercise the adapter against an authenticated disposable Mongo
replica, including valid bootstrap and grant, altered signatures, wrong
principal, replay, expired request and rollback. CI must run against the exact
reviewed commit.

## Provisioning still needed

An authorized infrastructure administrator must establish the independent
signing authorities, verify the subject, provision the three distinct Mongo
principals using an approved database-administration channel, and establish
an isolated runner and protected request handoff. No such channel was supplied
in the current session. Direct extraction of the backup vault's Mongo root
password was rejected by automatic approval review and must not be reproduced
through a wrapper or workflow. Once these prerequisites are concrete and the
backup/recovery contract is complete, implement and review the adapter and
workflow, test them without production credentials, then perform the signed
staging operation. Never infer a successful grant from a workflow dispatch;
verify the transaction and sign-in with the subject.

## Offline command adapter

`services/identity/cmd/role-operator` invokes the three existing operations
`schema`, `bootstrap` and `change`; it does not provision any identity or
read backup custody. Set `IDENTITY_ROLE_ENVIRONMENT=staging` and supply a
separately provisioned principal in `IDENTITY_ROLE_MONGO_URI`. The URI may use `mongodb` or `mongodb+srv` (Atlas), must
contain username and password, explicitly enable TLS, and may only contain
`tls`, `tlsCAFile`, `authSource`, `replicaSet`, and `directConnection`
options. Driver errors are not printed. Each operation needs its own
independently scoped Mongo principal.

For `bootstrap`, supply the pre-pinned governance public keys in
`IDENTITY_ROLE_TRUSTED_KEY_A` and `IDENTITY_ROLE_TRUSTED_KEY_B`, as lowercase
hex; for `change` supply the independently pinned operator and security
public keys. Send the short-lived, signed JSON request on standard input.
These keys are public; never provide private signing keys to the command.
The signature and statement field names are those of the bounded request
adapter in `roles/operator_adapter.go`. A successful exit means the Mongo
transaction committed; it does not verify subsequent browser access.

The command is also tested as a subprocess against a disposable authenticated
TLS replica, using separate synthetic schema, bootstrap, and executor
principals. The test checks that the schema and bootstrap principals cannot
perform the next operation. Separate unit tests reject insecure URI options.
Provisioned real trust roots, independent principals, and a protected network
path are still required before live use.
No executable workflow, production credential, or live database connection
is included in this change.

## Atlas network evaluation

`compose.identity.staging.atlas-evaluation.yaml` is a configuration fixture for
an external database path. It adds a dedicated, unrestricted Docker egress
network only to the Identity service; this is not a destination allowlist and
is not a deployable Atlas handoff. The current staging wrapper intentionally
rejects the extra network. No connection, DNS, Atlas account, credential or
backup changes are made by this overlay. Before a real switch, implement and
review an Atlas-specific deployment with appropriate outbound restrictions,
independent Mongo credentials, verified backup/restore and a tested rollback.

## Atlas custom role payloads

`python3 scripts/identity_staging_atlas_roles.py` prints four secret-free Atlas
Admin API custom-role payloads for the staging runtime, inventory, read-only
backup and dedicated quarantine restore users.
They match the current access-history-enabled Identity privilege checks; the
optional recent-access view is disabled. Atlas custom roles must be created
through Atlas UI, CLI or API, not Mongo `createRole`; see the [Atlas custom
roles documentation](https://www.mongodb.com/docs/atlas/security-add-mongodb-roles/).
These payloads are review material: generating them does not create roles,
users or credentials, and has not been tested against a live Atlas project.
Do not attach additional broad or built-in roles to these service users; the
service checks the effective privileges and will reject excess permissions.

The shared snapshot exporter also supports a separately provisioned Atlas
backup principal authenticated over the Mongo shell standard input. It is
tested against a disposable Mongo replica with collection-scoped read access.
This is an export primitive only: an Atlas backup runner, independent custody,
restore validation and automated retention remain necessary before cutover.
The current schema 2 snapshot does not include role governance policy/journal.

A separate `host/identity-atlas-staging-backup.py` runner is prepared for the
Atlas candidate. It reads only a root-private Atlas-specific configuration,
validates ownership of the fixed Compose egress network, sends the dedicated
backup credentials to `mongosh` over stdin, encrypts the bounded export and
writes an Atlas-specific receipt. It does not read local Mongo custody. It is
not installed, scheduled, connected to Atlas or a replacement for a tested
restore. Its Docker transport is covered by isolated orchestration tests; a
live Atlas end-to-end backup/restore remains a cutover prerequisite.

The quarantine restore primitive supports a separate Atlas restore user whose
role can read the five destination collections and insert only accounts,
inventory audit and access summaries. The transaction refuses a nonempty
destination and strips credentials, sessions, tokens and admin roles. The
operator must stop Identity first; no Atlas restore runner is installed or
authorized by this primitive, and live Atlas restore remains unverified.

## Independent Atlas custody

The manual `atlas-custody` action in `identity-staging-operations.yml` creates
or validates the separate OCI Vault secret `identity-staging-atlas-custody`.
It reads the GitHub Actions secrets `IDENTITY_ATLAS_STAGING_RUNTIME_URI`,
`IDENTITY_ATLAS_STAGING_INVENTORY_URI` and `IDENTITY_ATLAS_STAGING_BACKUP_URI`.
These are three separately provisioned Atlas database users on the same
staging cluster. This action validates them, creates an independent backup
key once and refuses implicit credential rotation. It does not inspect the
local Mongo operator bundle, create Atlas users, test connectivity, deploy the
service or change the active database. Never put credentials in workflow
inputs, logs, issues or chat. Add the GitHub secrets through the repository or
staging environment secret settings using an authorized administrator account.

The staging Identity image accepts `/app/identity preflight` with its protected
service configuration. It checks TLS-authenticated runtime and inventory
privileges and the writable replica without creating accounts, sessions or
indexes. The command emits only generic success or failure. It has been tested
against a disposable TLS replica with correctly scoped, insufficient and
overprivileged users, but not against a live Atlas cluster. Run it from the
actual candidate network before a cutover; backup, restore and public login
verification remain separate requirements.

The root-owned `identity-atlas-staging-prepare.py` preparation command reads
only the separate `identity-staging-atlas-custody` Vault secret and the current
service configuration; it does not read local Mongo root custody. It creates
separate mode-0400 Atlas service and backup configuration files, preserving the
current live file. Existing different Atlas files fail closed. The command is
not installed or invoked by the current workflow and does not deploy, connect
to Atlas or verify a backup.
