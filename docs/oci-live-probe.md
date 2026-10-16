# First real host readiness accredited — return to manual-only

Oracle authentication from ShadowOps was validated in OCI inventory run
[38874790800](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38874790800):
`SHADOWOPS_OCI_INVENTORY_OK`.

A separate trusted-main host probe was completed successfully in
[38875355662](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38875355662)
on 2026-10-16. Its `Nonprivileged host readiness via OCI Run Command` job
finished successfully and returned precisely
`SHADOWOPS_EXISTING_A1_HOST_PROBE_OK`.

The check verified the existing ARM64 A1, Docker/Compose, the
Chess Studio deployment wrapper and the staging backend's local
`/api/ready` endpoint. OCI Run Command created an execution record
and ran a **fixed nonprivileged read-only script**. No workloads were
restarted, deployed, or modified. No remote stdout was echoed to logs
(other than the fixed success marker).

**The workflow is now manual-only** for its credential-backed OCI host
job. PR and push runs execute mock contract tests only. The manual
workflow still requires protected ShadowOps `main`, the fixed adopted
host identity, a healthy Oracle agent and a strict success marker.

Next: isolate ShadowOps-controlled staging operations and prove
deployment/rollback with independently verified source artifacts
before transferring Chess Studio's live deploy authority. Do not
run competing OCI Terraform or Cloudflare tunnel reconcilers.
