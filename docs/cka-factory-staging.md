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

## Manual exact-SHA installer candidate (not executed)

[`host/install-cka-factory-staging.py`](../host/install-cka-factory-staging.py)
is a **root-operated host-side installer only**. No GitHub Actions workflow
calls it, and it is never invoked by the CKA frontend, OCI Run Command or
the source preflight. It cannot fetch code, build a package, install
dependencies, supply credentials, invoke inference, or start/enable services.

Before running it, an operator must independently stage TWO root-owned clean
immutable checkouts and the Python runtime:

- `/opt/shadowops-infra` checked out at the exact approved Infra SHA.
- `/opt/shadowops/cka-factory-staging/source` checked out at the exact
  approved CKA SHA. Its parents, git metadata and tracked source files
  must not be writable by non-root users.
- `/opt/shadowops/cka-factory-staging/venv/bin/python` is already a
  root-owned non-symlink executable, from a Python virtual environment
  provisioned with `python3 -m venv --copies`. Its installed `cka_sim`
  package must resolve its catalog root to the pinned CKA source checkout.
  A source-linked editable install is acceptable **only when the checkout
  itself is root-owned, frozen and validated**. The installer now also
  checks every entry within the virtual environment before importing it:
  only root-owned, non-group/world-writable regular files/directories are
  allowed (apart from Linux's standard `lib64 -> lib` compatibility link).
  This includes scripts, `.pth`, Python sources and installed metadata.
  The check is bounded to 80,000 entries and rejects external links and
  special files. The interpreter must report the **exact** expected
  `sys.prefix`, and `python -I -m pip check` must report no broken
  requirements. Root-owned files can still contain malicious code; this
  checks host integrity and dependency consistency, **not** a cryptographic
  wheel provenance certificate or a dependency vulnerability scan.
- Preprovision the SHARED parent directories `/var/lib/shadowops` and
  `/etc/systemd/system` with secure root ownership/permissions. The
  installer never creates or changes these parents or other products.

From a separately authorized interactive **root** shell on the trusted A1:

```bash
python3 /opt/shadowops-infra/host/install-cka-factory-staging.py \
  preflight <EXACT_INFRA_SHA> <EXACT_CKA_SHA>

# Only after independent review and approval of the manual host change:
python3 /opt/shadowops-infra/host/install-cka-factory-staging.py \
  install <EXACT_INFRA_SHA> <EXACT_CKA_SHA> \
  --confirm INSTALL_CKA_DRY_RUN_STAGING_ONLY
```

The read-only preflight checks SHA shape, exact Git repository root and
HEAD for **both** checkouts, and a clean tracked tree **without nonignored
untracked files** (including stray Python modules that could shadow imports).
It also checks root ownership and unsafe write permissions (including
ancestors), every virtualenv file's safety, actual venv identity and dependency
consistency, installed Python import-root identity, unchanged dry-run-only
`systemd` policy, existing unit integrity and any preexisting workspace/account.
Ignored files and the separately installed Python dependencies are NOT a
cryptographic supply-chain attestation; the operator must independently
verify that environment before using it on the host.

The `install` action performs those checks BEFORE changes; then creates
at most the non-login `shadowops-cka-factory` service account, private
`0700` workspace and the exact CKA unit. Unit installation stages the
complete content in the destination filesystem, fsyncs it and atomically
hard-links it **without replacing any existing file**. Failed publication
removes the temporary file rather than leaving a truncated systemd unit.
It does NOT replace existing units, change shared service directories,
contact OCI/Cloudflare, start or enable the service, execute Python
inference, add a timer or run `daemon-reload`. Installation is designed
to be idempotent after a valid first installation.

After explicit approval, a human operator may separately run
`systemctl daemon-reload`, inspect the installed unit and manually start
the **network-isolated dry-run** service. No automatic host installation or
smoke execution is provided by CI. If provisioning the runtime or operator
identity is not independently verified, do not run the install action.

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
