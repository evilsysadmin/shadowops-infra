# First live OCI inventory after credential custody handoff

**Scope:** OCI observation only, no host command, secret access, Terraform,
production deploy, Cloudflare mutation or OCI resource changes.

Chess Studio handoff run
[38874157975](https://github.com/evilsysadmin/chess-studio/actions/runs/38874157975)
completed successfully on 2026-10-16 with the expected
`SHADOWOPS_OCI_HANDOFF_OK` marker. The workflow wrote the four required OCI
Actions secrets to ShadowOps using its repo public key and verified **names
only**, not actual OCI authentication.

This PR enables ShadowOps's pre-existing read-only OCI inventory job on
protected `main` pushes that touch its inventory workflow or source. The PR
run executes **mock contracts only**, and cannot receive or use OCI credentials.
After merging, inspect the `ShadowOps OCI · existing A1 inventory`
`push` workflow run and require the live
`SHADOWOPS_OCI_INVENTORY_OK` marker before treating the credential handoff
as verified against Oracle.

This is intentionally path-scoped, not a recurring secret-powered heartbeat.
`workflow_dispatch` remains available for future explicit read-only checks.
Never remove the original Chess Studio OCI credentials until the controller
cutover is complete. The ephemeral `SHADOWOPS_BOOTSTRAP_TOKEN` in Chess
Studio must be deleted and its corresponding PAT revoked independently.
