# CKA staging lab pilot

The requested first candidate is the central ShadowOps account `evilsysadmin`.
This is an intended pilot restriction, not an active lab authorization. Bind
the eventual allowlist to its freshly verified Identity subject UUID; never
trust a username, GitHub identity, request parameter or signature alone.

The existing A1 runs Identity, Chronicles and shared account services. Student
workloads must run on a separate runner VM. The public CKA account service
must retain its existing isolation: no Docker socket, administrator kubeconfig
or lab execution imports. The local development API stays loopback-only.

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
