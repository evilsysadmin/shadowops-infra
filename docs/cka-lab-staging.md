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
