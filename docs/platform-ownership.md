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
