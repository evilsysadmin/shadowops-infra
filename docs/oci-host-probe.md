# OCI existing A1 — nonprivileged host readiness check

Run `ShadowOps OCI · existing host probe` manually from protected `main`
**after** OCI Actions secrets have been installed in ShadowOps.

The script authenticates against OCI, ensures there is exactly one RUNNING
`VM.Standard.A1.Flex` named `chess-studio-staging` in compartment
`chess-studio-staging` with an operational Run Command agent, then issues
a **fixed, nonprivileged** host observation. This OCI API operation creates a
Run Command execution record; the on-host script performs reads only.

The probe checks: ARM64 host, existing Chess Studio checkout/deploy wrapper,
Docker/Compose availability, active Docker daemon and Chess Studio's loopback
staging API readiness on `127.0.0.1:4000`. It emits one success marker and
never prints remote stdout or allows user-supplied commands.

**Never run a deploy from this tool.** No `sudo`, Docker writes, Git fetch,
SSH, Terraform, Cloudflare, OCI IAM changes, secret materialization or service
restart. A green PR validates behavior against mocks; a manual workflow run
with real OCI credentials is required to demonstrate host readiness.

This is one incremental step toward the transfer of all Matthias
infrastructure operations to ShadowOps without a second competing owner.
