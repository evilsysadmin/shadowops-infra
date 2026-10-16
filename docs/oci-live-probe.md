# First verified live host observation — OCI Run Command

The [ShadowOps OCI existing A1 inventory] workflow already demonstrated
real Oracle authentication (run 38874790800, `SHADOWOPS_OCI_INVENTORY_OK`).

The next trust gate is a **single read-only on-host smoke** issued as a
fixed OCI Run Command to the existing A1, not a Chess Studio deploy. This
commit enables the probe on the protected `main` push that changes its
own workflow. PRs run fake-SDK contract tests only; the workflow does
not have the OCI secrets or send a host command on a pull request.

On-host reads: `uname -m`, existing Chess Studio checkout and deploy
wrapper existence, Docker CLI/Compose availability, Docker daemon
activity, and localhost staging API `/api/ready` HTTP 200.
Run Command creates an OCI command execution record, and its
unprivileged agent *executes* that strictly static shell. No SSH,
sudo, Docker writes, service restart, Terraform or Cloudflare writes.

Success requires both a successful terminal execution and an exact
`SHADOWOPS_EXISTING_A1_HOST_PROBE_OK` marker from the remote command.
Remote stdout/stderr must never appear in the GitHub runner logs. The
probe is bounded to 12 minutes and uses a serialized control-plane group.

After verifying the first run, restore the workflow to manual-only in a
follow-up PR: avoid executing a secret-bearing cloud job merely because
a developer edited host-probe tests. Do not transfer actual Chess Studio
deployment ownership until the separate deployment/rollback gate is proven.
