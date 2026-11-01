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

## OCI Run Command delivery latency: evidence and safe triage

When a staging/prod release passes image admission but its OCI execution
waits a long time, **do not assume Docker/Compose or Vault is slow**.
The GitHub Actions job emits fixed-format **local controller observations**:

- `CHRONICLES_API_OCI_PHASE_SECONDS`: preflight, dispatch, elapsed execution.
- `CHRONICLES_API_OCI_DELIVERY_OBSERVED_SECONDS`: first *observed* nonterminal
  `ACKED` boundary, not the agent's exact acknowledgment time.
- `CHRONICLES_API_OCI_POLL_SECONDS` and `CHRONICLES_API_OCI_POLL_DETAIL_MS`:
  actual wall time spent on the already-existing OCI GET calls. The call
  first observing `ACKED` counts on the pre-ACK side.
- `CHRONICLES_API_OCI_DELIVERY_SAMPLES`: counts of nonterminal
  `VISIBLE`, `PENDING`, and other pre-ACK samples. **Counts are not
  seconds**; no `ACKED` seen before terminal does not prove it never occurred.
- `CHRONICLES_API_OCI_HOST_PHASE_SECONDS`: only displayed if the *installed*
  host wrapper includes that single strictly validated line. If missing,
  **do not infer the wrapper version or invent host timings**.

Two successful staging runs on 2026-11-01 (UTC) illustrate the issue:
[14:45 run](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41317776858)
reported 136s until observed ACK, 22s after, with 25.178s cumulative
pre-ACK OCI GET latency across 38 calls. The
[15:06 run](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41319531791)
reported 83s until observed ACK, 18s after, with 14.963s pre-ACK GET latency
across 24 calls. Each run's slowest OCI GET was under 0.8s. These
observations make one slow OCI GET an unlikely explanation, **not proof**
of which service, agent, or host component caused the waiting.

OCI delivery semantics (Oracle's
[InstanceAgentCommandExecution API](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/compute_instance_agent/models/oci.compute_instance_agent.models.InstanceAgentCommandExecution.html)):

| Observed delivery state | What it establishes | What it does not establish |
| --- | --- | --- |
| `VISIBLE` | Command visible to the instance | Agent has fetched or begun executing it |
| `PENDING` | Awaiting instance acknowledgment | The exact time or reason the instance has not acknowledged |
| `ACKED` | Agent acknowledged receipt | Host command start, script success or Docker duration |
| `EXPIRED` | Command delivery expired without an instance request | That restarting the agent is safe |

### Host-side check — authorized operator, no changes

First use **one existing completed workflow** and its exact UTC deployment
window. Never dispatch another command solely to benchmark the A1, especially
during another staging/production release. On a trusted operator session
already connected to the existing A1, inspect **locally**:

```sh
date -u
systemctl is-active oracle-cloud-agent
sudo stat -c '%y %s %n' /var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log
sudo less /var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log
sudo sha256sum /usr/local/sbin/shadowops-chronicles-api
```

In `less`, navigate to the same **UTC** window as the workflow (accounting
for the host log timezone); check whether command polling, receipt,
authorization errors, agent backoff or concurrency coincide with the
prolonged pre-ACK window. The installed wrapper's SHA-256 may be compared
**locally** with the operator's trusted, pinned checkout; a differing hash
needs investigation and does not prove a specific deployment version.

**Do not paste raw agent logs, command IDs, Vault IDs, environment values,
tokens, or host output into GitHub Actions or issue comments.** The log
may contain sensitive context. Record only sanitized event types, counts,
durations, and approximate UTC timestamps. Oracle documents the log location
and its Run Command limits in
[Running Commands on an Instance](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/runningcommands.htm).

The A1 also serves Chess Studio. This is **read-only troubleshooting**:
do not restart `oracle-cloud-agent`, change IAM/dynamic groups, increase
run-command workers, install a new wrapper, or change Docker/Compose on the
basis of these observations alone. Do not extend the `ocarun` sudo allowlist.
If the logs suggest plugin trouble, document the evidence and plan a
separately reviewed, coordinated remediation.
