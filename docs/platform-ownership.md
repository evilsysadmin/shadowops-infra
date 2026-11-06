# Matthias platform: infrastructure ownership and migration

Target owner: `evilsysadmin/shadowops-infra` — OCI, Cloudflare DNS/Tunnels/Pages,
Render controls, registry admission, deployment, rollback, secrets operations,
observability and backups for all Matthias games.

| Product | Source/build owner | Infrastructure owner (target) |
| --- | --- | --- |
| Chess Studio | `evilsysadmin/chess-studio` | ShadowOps Infra |
| Chronicles | `evilsysadmin/chronicles-of-matthias` | ShadowOps Infra |
| Future Matthias games | Their own dedicated repositories | ShadowOps Infra |

## Actual ownership — migration in progress

**Do not confuse target ownership with live ownership.** Chess Studio still
manages its production and staging release workflows, the OCI A1 bootstrap and
its Cloudflare tunnel/Pages DNS. ShadowOps must not concurrently reconcile
those same resource identities. Chronicles has an isolated API Compose contract
and separate web test image, but no verified public deployment.

The existing A1 (compartment `chess-studio-staging`, instance
`chess-studio-staging`, region `eu-frankfurt-1`) is the **adopted host**,
not a replacement resource. ShadowOps MUST NOT run an independent Terraform
apply or destroy for that shared resource while Chess Studio still owns its
OCI Terraform state and policies.

## Transition gates

1. **Credentials:** configure `OCI_TENANCY_OCID`, `OCI_USER_OCID`,
   `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY` privately as **ShadowOps Infra**
   Actions secrets (and optionally `OCI_REGION` as a variable). GitHub does
   not reveal another repository's existing secret values. Do not open an
   interactive runner session, paste signing keys into logs, or store them in
   Git. A scoped, audited one-time transfer is a separate operation; no token
   bridge or OCI Vault bootstrap is silently enabled by this change.
2. **Observation:** manually dispatch `ShadowOps OCI · existing A1 inventory`
   from protected `main`. It must discover **exactly** the existing A1 and
   a running Compute Instance Run Command plugin, without mutating state.
3. **Workload control:** add an explicitly allowlisted, isolated Chronicles
   read-only host preflight and then an authenticated staging deploy. Preserve
   exact digest admission, smoke and rollback. No Chess Studio host wrappers
   may be replaced.
4. **Chess Studio handoff:** first replicate and validate its currently
   working staging/release controls, then disable the old controllers in one
   reviewed ownership cutover. Keep its rollback and Render production intact.
5. **Cloudflare handoff:** transfer existing DNS/Tunnel/Pages identities
   with read-only inventory and no competing mutators; first prove the new
   reconciler preserves existing routes, then retire the old one.
6. **Future apps:** supply only a new product's immutable artifacts, scoped
   runtime configuration, admission policy and isolated smoke tests.

## Chronicles R2 public-edge observation (staged handoff)

The manually dispatched `Chronicles · public R2 edge proof (handoff)` workflow
runs on protected Infra `main` only, after its no-network contract test. It
uses no secrets and makes fixed HTTPS HEAD/GET requests for the known public
`assets.chronicles.shadowops.dpdns.org` mutable goblin alias and the pinned,
SHA-256-verified immutable goblin object. It rejects unexpected content type,
CORS, browser cache policy, public size/digest and redirects. Infra CI runs the
offline tests on **every** PR.

**Not an ownership cutover:** the existing Chess Studio
`chronicles-r2-public-probe.yml` still owns Cloudflare private bucket/domain
inventory. Odo/goblin publicators also remain there. Infra's edge proof does
not enumerate bucket objects, change Cloudflare resources, upload, delete or
acquire publishing credentials. First run the Infra workflow manually and
record the real public edge result, then separately design an inventory and
publishing migration with least-privilege credentials and proven rollback.
Until acceptance, do not disable the legacy operators or claim all R2 control
has transferred. A red public-edge proof must not trigger automatic changes.

## Chronicles R2 private inventory (shadow mode, not cutover)

The manually dispatched `Chronicles · private R2 inventory (handoff)` workflow
is independent of the public-edge probe. Its synthetic unit tests also run in
the normal Infra PR contracts gate. The live job is **manual on protected Infra
`main` only** and performs Cloudflare GET requests solely against the fixed
`chronicles` bucket's custom domains and paginated object list. It reports
counts, total bytes, a coarse sprites/music/models/other breakdown and the
number of objects that need privacy/manual review; it **never logs object
names, cursor values, raw API responses or credentials**. The active public
custom domain must be exactly `assets.chronicles.shadowops.dpdns.org`.

Before manual dispatch, provision `CHRONICLES_R2_READ_TOKEN` and
`CHRONICLES_R2_ACCOUNT_ID` as repository Actions secrets in **Infra**. Use
an independently scoped Cloudflare token with only the account-level R2 read
permissions required for bucket domain and object-list GET calls. Verify those
specific endpoints work; do not copy the existing full-access Chess Studio
token or grant object write, DNS, tunnel, account admin or Terraform rights.
If credentials are not configured, the job must fail closed, not fall back to
Chess Studio or an unauthenticated/public inventory. No secrets are available
to pull requests. A manual green result validates observation only; it does
not authorize content publishing or owner transfer.

**Sequence before retiring the Chess Studio operator:** (1) run the public
edge proof in Infra and preserve its SHA/response receipt; (2) configure and
run the private inventory in Infra, recording only sanitized metrics; (3)
compare the active domain and aggregate counts against the old Chess Studio
probe under a separately reviewed evidence process; (4) design a distinct
scoped publisher migration with rollback and explicit ownership cutover. Keep
`chronicles-r2-public-probe.yml` and the Odo/goblin publishers in Chess Studio
until the old and new capabilities have real matching evidence. A green PR CI
or a passed synthetic test is **not** live Cloudflare acceptance.

## Guardrails

- Infrastructure is **shared at the host level, not at the application
  identity/data level**. Separate Compose projects, ports, runtime secrets,
  staging/production databases and backups.
- CI on a PR never receives production or OCI credentials.
- The first OCI workflow is a **manual, read-only inventory**; no apply,
  deploy, SSH, cloudflared rewrite, secret transfer or host command.
- Never treat green GitHub checks as proof that credentials are configured,
  OCI is reachable or a game is deployed.
- Protect ShadowOps `main`, enforce reviewed PRs and required CI before
  enabling any mutating infrastructure workflow. As of the initial owner
  adoption, the branch-protection flag requires independent verification.
