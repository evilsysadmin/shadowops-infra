# CKA staging lab pilot

The requested first candidate is the central ShadowOps account `evilsysadmin`.
This is an intended pilot restriction, not an active lab authorization. Bind
the eventual allowlist to its freshly verified Identity subject UUID; never
trust a username, GitHub identity, request parameter or signature alone.

The existing A1 runs Identity, Chronicles and shared account services. Student
workloads must run on a separate runner VM. The public CKA account service
must retain its existing isolation: no Docker socket, administrator kubeconfig
or lab execution imports. The local development API stays loopback-only.

## Always Free only

The owner explicitly requires Always Free capacity only. The fixed runner
candidate is A1 Flex with 1 OCPU, 6 GiB RAM and a 50 GiB boot volume, in the
tenancy's home region. No paid fallback, shared-host lab, resize or automatic
allocation is authorized by a capacity report.

The [current Oracle Always Free documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
specifies a conservative total A1 envelope of 2 OCPUs / 12 GiB (1,500 OCPU-hours
and 9,000 GB-hours per month), plus 200 GiB combined boot/block storage.
Do not assume the historical 4 OCPU / 24 GiB allowance.

`scripts/cka_lab_free_capacity.py` observes root and all nondeleted compartments,
all home-region availability domains, A1 VM/container consumption and detached
boot/block volumes. Stopped/terminating resources still count conservatively.
Missing permissions, incomplete results, unknown A1 shapes, ambiguous identities
and a non-home region stop the preflight. Logs contain aggregate capacity only.
The fixed existing runner, if present, must match its size and compartment and
is not counted as a second allocation.

This read-only check emits `CKA_ALWAYS_FREE_CAPACITY` and reports capacity fit;
it does not create a VM, prove current-month billing or host availability, inspect
image licensing, configure network services, or enable labs. A future allocator
must repeat the checks immediately before creation and validate those remaining
free-only conditions. The original shared-host inventory alone is insufficient.

The existing OCI inventory workflow now also reports read-only capacity in the
adopted `chess-studio-staging` compartment, and whether a distinct nonterminated
instance named `cka-lab-staging` exists. It prints CPU/memory and lifecycle only;
no instance identifiers, IP addresses, user data or credentials. PRs run offline
tests; credential-backed observation runs only on trusted Infra main. This
inventory does not grant access, run a remote command or allocate compute.
Absence is scoped to that compartment; it does not establish tenancy-wide
availability, quotas, price or Always Free eligibility.

Before an Internet lab pilot: verify dedicated compute, durable owner-bound
leases, one active session globally, bounded TTL and resource quotas, cleanup
after expiry/restart, candidate-scoped Kubernetes permissions and admission,
fresh account authorization per operation, an audited restricted terminal, and
real-kind fail/repair/pass plus isolation tests. Deployments remain Infra-owned.
The three curated scenarios need those checks before enabling prepare/grade.
