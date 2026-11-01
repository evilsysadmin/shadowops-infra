# CKA staging lab pilot on the shared A1

The owner selected Docker Compose on the existing A1 for the initial restricted
pilot, with no new VM, paid fallback, host resize or change to the other products.
This supersedes the earlier dedicated-runner requirement for this staging pilot.
Production and untrusted multi-user laboratories still need their own reviewed
isolation and capacity decision.

The first candidate is the central ShadowOps account `evilsysadmin`. Bind its
allowlist to the freshly verified Identity UUID; a username or browser parameter
is never a lab authorization.

## Separate Compose project, same physical host

The proposed project is `shadowops-cka-lab-staging`. The existing
`shadowops-cka-account-staging` service remains account-only: no Docker socket,
administrator kubeconfig or lab imports. Keep Identity and Chronicles containers,
networks, credentials and persistent volumes unchanged.

Kubernetes must run inside a dedicated unprivileged runtime/user namespace on
the shared host. Do not silently substitute a privileged node on the host Docker
daemon when rootless prerequisites fail. The lab controller may hold only the
lab cluster's credentials, never host Docker authority. Candidate commands use
their namespace-scoped Kubernetes identity; no credential reaches the browser.
The existing local development API remains loopback-only and is not the staging API.

Start with one active lease globally, a fixed CPU/memory envelope, durable
owner-bound lease state, expiration/restart cleanup, restricted pod admission,
resource quotas and no route from candidate pods to host services or metadata.
Only curated exercises may be prepared. Grading must read real Kubernetes state.

## Measure before installing or starting

`scripts/cka_lab_host_preflight.py` submits one fixed nonprivileged observation
to the adopted A1 through OCI Run Command. It reads available/total memory,
CPU/load, available disk, cgroup v2/user namespaces, rootless helper availability
and whether the fixed lab wrapper exists. `sudo -l` observes current policy;
no root command is executed and the rules themselves are never printed.

The minimum candidate headroom is 3 GiB available memory and 12 GiB free disk.
That permits budgeting up to 2 GiB for the cluster, 256 MiB for the controller
and 128 MiB for the tunnel, with reserve; these are proposed limits, not measured
workload requirements or a current resource reservation. CPU limits, real cgroup
delegation and a bounded private disk must also be verified before activation.
Repeat the observation immediately before deployment.

PRs run offline behavior tests only. A protected-main push or manual dispatch of
`cka-lab-staging.yml` runs the observation with Infra's existing OCI credentials.
Output is a strictly validated aggregate receipt, never raw remote stdout,
host identifiers, sudo rules or credentials. Missing OCI stdout is missing
evidence, even when the execution exits successfully. Green CI does not install
the runtime, add privilege, start Kubernetes or enable a public lab.

A first reviewed operator installation must establish the dedicated runtime and
fixed argument-validating lab wrapper. Existing product wrappers cannot install
it or be used to obtain a root shell. The observation reports existing authority
without granting any.

## Always Free only

No extra compute allocation is part of this pilot. The earlier read-only
`cka_lab_free_capacity.py` tenancy inventory remains available for capacity
planning; its separate-VM projection is not the selected deployment topology.
[Actual inventory run](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41223478612)
observed 1 OCPU, 6 GiB RAM and 50 GiB of boot/block storage in use across three
home-region compartments, with no dedicated runner.

The [current Oracle Always Free documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
specifies a conservative A1 envelope of 2 OCPUs / 12 GiB and 200 GiB combined
boot/block storage. It is not an instruction to allocate that capacity.

## Activation acceptance

Before enabling prepare/terminal/grade: verify actual host headroom and enforced
limits, the installed runtime policy, fresh Identity authorization on each
operation, pilot UUID binding, durable capacity-one leases, bounded TTL and
verified cleanup after expiry/restart, candidate RBAC/admission/network isolation,
and all three curated exercises failing initially then passing after real repair.
Verify the actual staging browser journey and that logout denies further lab
operations. Deployment and rollback remain Infra-owned.

## First operator installation: rootless runtime only

The actual [shared-host preflight](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41225557143)
observed 4,095 MiB available memory, 25,904 MiB free disk, cgroup v2 and user
namespaces. It also proved `operator_sudo=false`, no lab wrapper and missing
rootless helpers. Actions cannot install this first policy through the existing
product wrappers. The host observation is a snapshot, not a reservation.

From the existing clean root-owned protected Infra checkout on the A1:

```bash
cd /opt/shadowops-infra
sudo git fetch origin main
cka_runtime_sha="$(sudo git rev-parse origin/main)"
sudo git checkout --detach "$cka_runtime_sha"
sudo python3 -I host/install-cka-lab-staging.py preflight "$cka_runtime_sha"
sudo python3 -I host/install-cka-lab-staging.py install "$cka_runtime_sha"
```

The installer rechecks exact source bytes, root ownership including Git
metadata, clean protected-main identity, architecture, cgroup/user namespaces and
actual headroom before mutation. It installs only missing UID-map/rootless
network/FUSE/user-D-Bus prerequisites from the existing OS package sources.
It never replaces or restarts the shared Docker engine.

The new non-login `shadowops-cka-lab` user has no privileged group membership.
Its rootless daemon runs through a user systemd unit. Per-user root-owned
drop-ins cap the entire user slice at 55% CPU, 2,816 MiB memory, zero swap and
1,024 tasks. Its data/home live on a dedicated 8 GiB loop filesystem inside
the existing boot disk; no extra OCI volume is allocated. Host-loopback access
from the rootless network is disabled. Only the reviewed vendored Moby launcher
is executed as this user; no downloaded installer is piped into a shell.

The installer refuses foreign users, subordinate-map collisions, symlinks,
user-writable policy ancestors, different existing policy bytes and foreign
mounts. Root never traverses user-writable home contents to enable the unit:
that small operation is executed as the unprivileged runtime user.

Final marker: `CKA_LAB_ROOTLESS_RUNTIME_INSTALLED ... labs_enabled=false`.
The fixed `/usr/local/sbin/shadowops-cka-lab-staging inspect` independently
checks installed policy hashes, the exact loop backing file, live cgroup values
and the actual daemon's rootless identity/systemd driver. The OCI agent receives
only this inspection command, never generic sudo, Docker, install or shell access.

This step starts the empty bounded rootless daemon only. Kubernetes, controller
images, credentials, tunnel routes and public labs are not installed or enabled
by this bootstrap. Do not use an inspection marker as browser acceptance.


## Verify the installed rootless runtime through GitHub (read-only)

After the initial privileged operator installation, dispatch the
[CKA lab staging workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/cka-lab-staging.yml)
from protected `main`, choosing `inspect-runtime`. The workflow uses
the **existing narrowly allowlisted** OCI agent sudo command:
`sudo -n /usr/local/sbin/shadowops-cka-lab-staging inspect`.

The inspector independently verifies the dedicated non-login user, exact
installed policy hashes, private 8 GiB filesystem backing, live user-slice
CPU/memory/swap/PID limits and the actual rootless Docker daemon.
It emits only a strictly validated `CKA_LAB_RUNTIME_VERIFIED` summary
containing the installed source SHA and `labs_enabled=false`.

Missing installation, a missing sudo rule, an unhealthy OCI agent, a failed
command, ambiguous/extra output or malformed receipt all fail closed. This
**does not** install prerequisites, create Kubernetes, deploy the lab API,
enable a tunnel or activate the browser. Select `host-preflight` for the
existing nonprivileged capacity observation. PR checks remain offline.

## Rootless Kubernetes bootstrap under review

`scripts/cka_lab_cluster.py` creates only the fixed `cka-lab-staging` cluster
inside the dedicated rootless daemon. It refuses existing containers, bridges
and state, requires cgroup v2/systemd, pins kind v0.31.0 and Kubernetes v1.35.0
by the upstream node-image digest, and creates a separate internal IPv4 Docker
bridge. The API stays inside that bridge; no host API or application port is published.

After kind initialization, the node is capped at 2 GiB RAM, zero swap, 40% CPU
and 768 tasks. The encompassing user slice limits apply during bootstrap too.
The only host bind is kind's read-only `/lib/modules`; writable node data is
an anonymous volume in the bounded rootless data filesystem. Controller and
tunnel must never receive this daemon's Docker socket. Both curated workload and
network-probe images are pinned and preloaded; candidate pods cannot pull them
over an external route.

CI uses a disposable rootless daemon to run this actual bootstrap, checks the
node's live cgroup files, and exercises all curated scenarios through the real
Go journal and candidate driver. A restricted probe Pod must fail TCP connections
to a public positive-control destination and OCI metadata. The external host
first proves the public destination is reachable. This is an additional network
gate, not a claim of multi-user or production acceptance.

A bootstrap receipt always says `labs_enabled=false`. This PR does not execute
bootstrap on the A1, configure Identity or start a public controller/tunnel.
The runtime user can provision the checksum-pinned kind binary into its private
bounded home without installing any host-wide tool. The node restarts with the
rootless daemon; controller restart closes and reaps previous leases. Never run this against host Docker
or reuse the developer cluster.



## Signed CKA controller image admission (no OCI mutation)

The lab source repository builds and publishes `ghcr.io/evilsysadmin/cka-lab-staging`
after all source checks pass. Publishing alone does **not** authorize deploying
that image on the shared A1. Infra independently verifies it before admission.

From protected `main`, manually dispatch the
[CKA lab image admission workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/cka-lab-image-admission.yml)
with the exact CKA protected-main commit SHA and its published **multiarch
manifest** digest (`sha256:...`). The independent check rejects non-main or
superseded source commits, requires successful completed `push` workflows
`CI`, `Go scenario contract`, `CKA restricted lab staging` and
`CKA account staging`, verifies precisely one Linux ARM64 and one Linux
AMD64 image, and uses `gh attestation verify` with the pinned CKA signer
`.github/workflows/lab-staging.yml`, protected-main source ref,
exact source commit and SLSA provenance subject digest.

Only an explicit `CKA_LAB_IMAGE_ADMITTED` receipt containing the immutable
digest and source SHA is positive evidence. The check never issues a Docker
run, Compose command, host Run Command, credential copy, environment change,
lab enablement or OCI resource mutation. PRs exercise offline negative fixtures and a fixed **read-only** live
positive control using a published CKA multiarch digest and its existing
signed provenance. The positive control does not admit new artifacts or deploy
anything, and does not replace an explicit protected-main manual admission.
If CKA source main advances, update the reviewed positive-control fixture
to a verified newly published commit/digest pair before expecting it to pass.
A missing/ambiguous/invalid receipt is not approval.

This independent source admission does not replace the subsequent operator
confirmation of a healthy installed rootless runtime, actual A1 scenario smoke,
Identity pilot binding, tunnel route and controlled frontend activation.
The admitted digest must later be carried unchanged into
`CKA_LAB_IMAGE_DIGEST` in the dedicated rootless Compose project.

## Private Compose deployment contract

`compose.cka-lab.staging.yaml` contains the separate controller and tunnel.
It requires an admitted immutable `cka-lab-staging` image digest. Never execute
it against the host Docker daemon. The controller receives only the lab
kubeconfig, its own CKA service credential/JWKS/pilot UUID configuration and its
durable lease directory. It has no Docker socket, host paths outside the private
runtime, developer API, inference code or route to another product's Docker
network. Both IP forwarding sysctls are disabled on the controller.

The node/controller/tunnel CPU limits sum to 55%; memory caps sum to 2,432 MiB,
leaving 384 MiB of the 2,816 MiB user slice for the runtime. The whole slice still
bounds all processes, including helper/subprocess overhead. Controller UID 0 is
inside the rootless namespace and maps to the non-login lab user, so it can read
that user's private 0600 files; all capabilities are dropped and privilege
escalation is disabled. It is not host root.

After the first rootless operator installation, from protected Infra source:

```bash
sudo -u shadowops-cka-lab python3 /opt/shadowops-infra/scripts/cka_lab_cluster.py install-tools
sudo -u shadowops-cka-lab python3 /opt/shadowops-infra/scripts/cka_lab_cluster.py bootstrap
sudo -u shadowops-cka-lab python3 /opt/shadowops-infra/scripts/cka_lab_cluster.py verify-cluster
```

The last command is **read-only** and emits `CKA_LAB_CLUSTER_VERIFIED`
only after independently checking the existing rootless daemon, private
internal bridge, bounded/running kind node, private 0600 credentials,
unchanged kind configuration and actual Kubernetes `/readyz`. Every
unexpected or unhealthy state fails closed. It does not create/restart a
container, heal the cluster, read private credential contents, enable labs,
deploy a controller or grant a user access. Repeat it after a host reboot
before considering Compose activation. CI runs the same inspection against
its disposable rootless kind cluster.

These prepare only the fixed cluster. The second command refuses existing
containers/state instead of adopting or deleting them. Failed bootstrap keeps
its private state for diagnosis. No public application port, identity enrolment
or tunnel is created by these commands.

The node entrypoint needs a fixed Docker-host DNS alias on an internal network.
The private bootstrap supplies that alias and kind's documented endpoint-label
override only to the pinned node run. The resulting API endpoint is the real
container-network endpoint. No external network or fake successful probe is
substituted. The FUSE image preload uses containerd's local importer and confirms
the resulting CRI configuration digest against the original digest-pinned pull.

Activation still needs: the operator's freshly verified pilot UUID, a private
configuration copied from the existing CKA consumer credentials without IdP
signing keys, an admitted image, the lab tunnel/DNS route, real A1 scenario and
isolation receipts, and the dedicated `lab-staging` browser release. Neither the
existing account service nor the account-only Pages build activates labs.


## Published controller with real Compose and Kubernetes in disposable CI

The rootless workflow now also runs the exact signed published controller image
through `compose.cka-lab.staging.yaml`, using real namespace preparation,
candidate commands, live grades and durable restart cleanup. It independently
verifies protected-main source CI, the immutable multiarch digest and signed
provenance before pulling the image. The program is explicitly CI-only and has
no OCI credential, SDK or host installation path.

Only private bind-file locations and the native runner platform differ from
the real Compose definition. CPU/memory/swap/PID limits, read-only filesystem,
capability removal, private cluster network and both disabled forwarding
sysctls are checked on the actual running controller. No Docker socket or
Kubernetes credential is mounted in the candidate HTTP client.

A separate synthetic TLS authority issues fresh Ed25519 CKA tokens and verifies
their exact live JTI/session relationship. Its generated CA is trusted only in
these disposable containers, through a test-only read-only CA mount. The public
Identity URL, hostname verification, service authentication and controller code
remain unchanged. No real password, cookie, signing key or service credential
is used or read. The synthetic authority is never copied into a service image.

The client proves every curated exercise starts broken, accepts its scoped
repair and passes through the actual API. With the controller attached to its Identity egress network, a restricted Pod
must still fail public and metadata TCP connections against a successful external
positive control. The client then holds an unexpired token,
revokes the synthetic session, and requires five independent live freshness
checks to deny capabilities/status/command/grade/finish. This prevents a local
rate-limit denial from masquerading as revocation evidence. A still-active
lease must remain present until a real controller restart closes, deletes and
reconciles it. A subsequent attempt must work and leave no namespace behind.

This replaces the earlier source-built driver shortcut in the rootless job;
the published image supplies the actual Go helper, candidate driver and API.

Positive evidence is `CKA_LAB_PUBLISHED_COMPOSE_API_VERIFIED`, with the tested
source/digest, three exercises, current Identity checks, unexpired revocation,
restart cleanup and `oci_mutations=false`. It tests a fixed signed publication;
it does not perform live release admission, install the A1 runtime, bind a real
pilot UUID, create a tunnel, publish Pages or establish deployed acceptance.
