# CKA Workers AI factory · staging source handoff

This is a **credential-free GitHub runner preflight**, NOT a deployment to OCI A1.
App owner: [cka-exam-simulator](https://github.com/evilsysadmin/cka-exam-simulator).
Infrastructure owner: ShadowOps Infra. Public CKA remains a static read-only
Cloudflare Pages preview. No auth, kubeconfig, exam runner or inference is exposed.

## Manually run the preflight

From ShadowOps Infra **main**, choose **Actions → CKA Workers AI factory · staging
source preflight → Run workflow**. Optionally provide the exact current CKA
main 40-hex commit SHA; unknown, malformed or superseded SHAs are refused.
No secrets or OCI credentials are requested. A PR only runs contract tests.

The job checks out exactly that CKA SHA, installs its backend Python package,
then calls `python -m cka_sim factory-run` in dry-run mode with the provider
fixed to Workers AI and credential environment values blank. It verifies
no inference was made, no quota was consumed, and no proposal YAML appeared.
It checks both upstream main SHAs again before emitting a small receipt.

Successful execution yields `CKA_FACTORY_STAGING_PREFLIGHT_OK <sha>` and
artifact `cka-factory-staging-preflight-<sha>` recording the immutable app SHA,
mode `staging-source-preflight-only`, zero inference and **no OCI host touch**.
PR/CI green alone is **not** proof this manual preflight was invoked.

## Staging systemd dry-run candidate (not installed)

[`host/cka-factory-staging.service`](../host/cka-factory-staging.service)
is a **proposed manual one-shot unit**. It is intentionally **not** installed,
enabled, triggered by a timer, started by GitHub Actions or provisioned through
OCI Run Command. Its only `ExecStart` runs the pinned CKA `factory-run`
CLI in **dry-run mode** using `--workspace
/var/lib/shadowops/cka-factory-staging`; it has **no `--execute`**.

Host prerequisites, to be separately approved before any manual installation:

- Provision a dedicated system account `shadowops-cka-factory` with no login,
  no sudo privileges, and access only to its own persistent workspace.
  The root-owned application location
  `/opt/shadowops/cka-factory-staging/venv/` must contain a verified
  immutable-SHA installed backend, not a mutable editable checkout.
- Preprovision `/var/lib/shadowops/cka-factory-staging` as an absolute,
  real (non-symlink), persistent directory owned by that account, mode
  `0700`. Ensure the rest of `/var/lib/shadowops` and all Chronicles/Chess
  Studio directories remain untouched. The unit **does not** create or chown
  shared parents.
- If manually installed in an approved change window, the unit has
  `ProtectSystem=strict`, a single `ReadWritePaths` exception, private
  network namespace, `IPAddressDeny=any`, AF_UNIX-only sockets, dropped
  capabilities, no elevated privileges, bounded memory/tasks and no
  `[Install]` target. It is not a worker or service listening on any port.
- The dry-run unit cannot access Cloudflare, read backend secrets, or
  perform an inference. A *separate reviewed design and authorization* must
  exist before introducing an inference-capable one-shot unit with outbound
  HTTPS and restricted secret injection. Do not change this unit in place
  to add `--execute` or credentials without another reviewed staging PR.
- CI validates the unit **as a static contract** without invoking systemd.
  Passing these tests cannot prove the unit has been installed or executed.

The manual GitHub source preflight now uses an **ephemeral external workspace**
with `factory-run --workspace ...` and checks the lock exists but budget/YAML
have not been created. The preflight remains credential-free and cannot
touch an OCI host.

## What remains to be deployed

1. Establish the **dedicated staging OCI A1 owner, service account and durable
   private directories** for `.local/factory-budget.json` and
   `scenarios/generated/`; avoid symlink shortcuts and ensure storage survives
   source updates. Do not host or expose the dev API.
2. Provision **separate restricted Workers AI backend secrets** with the
   appropriate account and API permissions, not an unreviewed reuse of the
   Cloudflare Pages publisher token. Restrict egress to required HTTPS and
   audit external account-level inference/billing limits.
3. After source preflight, require explicit authorized staging installation,
   exact-SHA attestation and an operator-requested single Workers AI inference;
   check quarantine, sanitized logs and local daily budget.
4. Keep generated scenarios behind policy audit, real disposable-kind smoke,
   SHA-matched review, an explicit human review draft and a separate Git PR.
   Do not wire inference to any public student route.
5. Do not expose Kubernetes student labs until the dedicated Identity staging
   service, audience validation, per-user sandbox isolation, quotas and
   session TTL are independently proved.

**Boundary:** The preflight does not call OCI APIs, inspect an A1 host,
validate Cloudflare credential permissions, prove billable inference, install
any services, create systemd units, enable timers or change production.
It is an initial reproducible **source compatibility** and ownership gate.
The backend-side runbook is in
[CKA source docs](https://github.com/evilsysadmin/cka-exam-simulator/blob/main/docs/oci-a1-scenario-factory.md).
Issue: [CKA #9](https://github.com/evilsysadmin/cka-exam-simulator/issues/9).
