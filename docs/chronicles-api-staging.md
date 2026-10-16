# Chronicles API · staging runbook

`chronicles-api-staging.shadowops.dpdns.org` → own Cloudflare Tunnel
`chronicles-staging` → `chronicles-tunnel` (cloudflared) → `chronicles-api`
container on the shared A1 (project `shadowops-chronicles-staging`, loopback
`127.0.0.1:18081`). The API is Chess Studio's Go backend copied verbatim in
`evilsysadmin/chronicles-of-matthias/api`, with its **own** MongoDB database
(`chronicles_staging`), JWT secret and invite code: accounts and runs are
independent of Chess Studio.

Supersedes the earlier read-only placeholder (`compose.yaml` +
`compose.staging.yaml` + `scripts/oci_staging_deploy.py`), which no workflow
runs; retire those files in a follow-up.

## Secrets (ShadowOps Actions)

| Secret | Content |
| --- | --- |
| `CHRONICLES_STAGING_MONGO_URL` | Atlas URL of a user with `readWrite` on `chronicles_staging` only, no DB path |
| `CHRONICLES_STAGING_JWT_SECRET` | `openssl rand -hex 32` |
| `CHRONICLES_STAGING_INVITE_CODE` | Code required to register |
| `CLOUDFLARE_API_TOKEN` | Needs *Account · Cloudflare Tunnel · Edit* and *Zone · DNS · Edit* |

They reach the A1 only through OCI Vault: the provision job writes ONE
secret, `chronicles-staging-runtime-env`, and the host wrapper reads it with
the A1's Instance Principal. Nothing secret travels in Run Command or logs.

## One-time host install (operator machine)

```sh
host/bootstrap-chronicles-api-over-ssh.sh   # installs current protected main
```

Installs the root-owned wrapper `/usr/local/sbin/shadowops-chronicles-api`,
its Compose policy, a root-owned OCI SDK venv and a sudoers rule that lets
Oracle's `ocarun` call **only** that wrapper. Starts no container.

## Release

1. `Chronicles API staging` → *Run workflow* → `provision` (tunnel, DNS, Vault).
   Re-run after rotating any secret.
2. Same workflow → `deploy` (optionally a Chronicles main SHA). It admits
   `ghcr.io/evilsysadmin/chronicles-api:staging-<sha>` only if the image is
   on protected main, has linux/arm64 and carries build provenance from
   `chronicles-of-matthias/.github/workflows/api.yml`; then the wrapper
   writes the env files, brings up API + tunnel and smokes `/api/health` and
   `/api/ready` (MongoDB ping). The job finally smokes the public hostname and
   CORS for `https://staging.chronicles.shadowops.dpdns.org`.
3. Point the game at it: the Pages release builds with
   `VITE_API_URL=https://chronicles-api-staging.shadowops.dpdns.org/api`.
