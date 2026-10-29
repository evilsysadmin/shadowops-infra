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
