# ShadowOps Infra

**Canonical infrastructure control plane for ShadowOps products**: Chess Studio, Chronicles, CKA Simulator and future games/services.

Application repositories own **source, tests and immutable build artifacts**.
ShadowOps Infra owns **OCI/Cloudflare infrastructure, deployments, runtime
configuration, promotion/rollback and shared SRE automation** once each
resource's ownership has been explicitly transferred and verified.

**Adoption is incremental, never implied by this README.** A PR or green CI
does not prove ownership transfer or a running production service.

## P0 — ShadowOps Identity before new CKA authentication

See [platform roadmap](docs/ROADMAP.md), [Identity isolation / migration ADR](docs/identity-platform.md)
and [tracking issue #287](https://github.com/evilsysadmin/shadowops-infra/issues/287).

Target: separate **Identity Staging** and **Identity Production**, each serving
all products of its own environment; no cross-env user DB, signing keys,
cookies, secrets, issuer trust or permissions. **Not deployed yet.**
Use Strangler Fig + Branch by Abstraction + Expand–Contract to migrate the
existing Chess Studio IdP and Chronicles SSO, with rollback and no big-bang cutover.

Authenticated public CKA labs are blocked by this P0, but local kind labs,
CI and the read-only Pages preview remain independent.

Infrastructure handoff procedures remain in
[platform ownership](docs/platform-ownership.md). Release/deploy automation
must continue to pass exact-SHA gates, including validated staging and
production separation.

## CKA staging operator commands

From this repository on your operator workstation, with `make`, Bash, Git,
OpenSSH and a working `cloudflared` installation:

```bash
make help
make cka-lab-bootstrap
make cka-lab-inspect
```

After the runtime inspection succeeds, prepare the private Kubernetes cluster:

```bash
make cka-lab-cluster-bootstrap
make cka-lab-cluster-verify
```

The first command fetches the exact current protected Infra main on the A1,
verifies the installed runtime, then runs the pinned tool installation,
cluster bootstrap and live verification as `shadowops-cka-lab`. It does not
rerun the rootless-runtime installer. Allow several minutes for pinned image
downloads and initialization on the bounded A1. The bootstrap refuses existing
cluster state rather than adopting or deleting it; use the inspection target
for an existing cluster. Verification uses the existing root-owned source without fetching, changing
the checkout, installing tools or creating state.

Success includes `CKA_LAB_CLUSTER_VERIFIED` with `kubernetes_ready=true` and
ends with `CKA_LAB_OPERATOR_CLUSTER_BOOTSTRAP_COMPLETED labs_enabled=false`. This is the
private cluster only. API credentials, the lab tunnel, browser publication and
authenticated live acceptance remain subsequent steps.

If `cloudflared` is an asdf shim without a selected version, select one you
already have installed. For example, where version 2026.10.7 is available:
`ASDF_CLOUDFLARED_VERSION=2026.10.7 make cka-lab-bootstrap`.

`cka-lab-bootstrap` uses the existing Cloudflare SSH tunnel to
`ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org`. Sign in to Cloudflare
Access as usual and use your already-authorized Ubuntu SSH identity with
noninteractive sudo. For an existing non-default key, use
`CKA_OPERATOR_SSH_KEY=/path/to/key make cka-lab-bootstrap`; the key stays on your
workstation. Normal SSH host-key verification remains enabled.

The helper resolves current protected Infra `main`, verifies the root-owned,
clean `/opt/shadowops-infra` checkout, rechecks the exact SHA on the A1 and runs
the existing installer preflight, installation and runtime inspection. It stops
on local checkout changes or a moving source; it never resets or cleans your
files. The first install creates the bounded dedicated rootless user/runtime,
using 8 GiB of the existing boot disk and no new OCI VM or volume.

Success ends with `CKA_LAB_OPERATOR_BOOTSTRAP_COMPLETED labs_enabled=false`.
This prepares the runtime; Kubernetes, real Identity configuration, the lab
tunnel and browser activation remain subsequent deployment steps.
`cka-lab-inspect` only invokes the fixed installed inspector: it performs no
Git checkout, installation, service start or repair. It fails if the runtime
has not been installed. See the [full CKA lab runbook](docs/cka-lab-staging.md).

If SSH disconnects during bootstrap, installation status is unknown: inspect
before attempting another install. When the SSH tunnel is unavailable, run
the GitHub Actions workflow **CKA labs · shared A1 Compose preflight** from
`main` with `action=inspect-runtime`. This invokes only the installed read-only
wrapper through the OCI agent and may queue behind other A1 host operations.
The installer prints `CKA_LAB_INSTALL_STAGE` progress markers. Its APT calls
suspend `needrestart` for that process only, simulate the dependency plan and
reject upgrades, removals or pending configuration of existing host packages.
