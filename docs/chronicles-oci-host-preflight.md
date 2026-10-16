# Chronicles on the existing OCI A1: reserved-port preflight

ShadowOps now has validated OCI identity and read-only Run Command access to
the adopted `chess-studio-staging` A1. Before considering a first isolated
Chronicles deployment, manually run **ShadowOps OCI · Chronicles A1
reserved-port check** from protected ShadowOps `main`.

The job validates the **fixed** A1 identity, Run Command agent and host
architecture, checks the existing Chess Studio staging ready endpoint, then
uses the nonprivileged host's `ss` to reject any current TCP listeners on
**18081** (Chronicles API) or **18082** (Chronicles web). It returns only
`SHADOWOPS_CHRONICLES_A1_PORTS_AVAILABLE` on success.

This is an intentionally narrow, read-only **preliminary check**:
- It does not use sudo, SSH, Docker daemon access, environment dumps or secrets
  on the host, and never exposes raw Run Command output.
- An OCI Run Command record is created, but there is no file mutation,
  deployment, service restart, Cloudflare change or Terraform apply.
- A port with no listener may still be reserved by an existing *stopped*
  Docker container, or may become occupied after the probe. **The full Docker
  collision census in `scripts/shared_a1_host_guard.py` remains mandatory**
  just before every deployment; the result of this probe cannot replace it.
- A failed result means **do not deploy**. Diagnose manually, without
  changing Chess Studio workloads or starting competing controllers.
- A successful result does **not** imply Chronicles is live, its image or
  credentials are ready, or its database or public DNS exist.

PRs and ordinary pushes only run offline mock tests. The credential-backed
probe requires an explicit workflow dispatch on protected ShadowOps `main`.
This check should not be rerun as an always-on heartbeat.

## First live snapshot — 2026-10-16

Protected-main push [38879214696](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38879214696)
passed the real, credential-backed OCI Run Command preflight with marker
`SHADOWOPS_CHRONICLES_A1_PORTS_AVAILABLE`. Both reserved ports had no
TCP listeners **at the time of this observation**, and the existing Chess
Studio staging readiness check also passed. This is **not** proof of Docker
project ownership, future port availability or any Chronicles deployment.
The temporary push admission was removed immediately afterward; use manual
dispatch for further checks.
