# Star Adventures · exact Pages fail-closed policy

The live read-only audit [run #44795421159](https://github.com/evilsysadmin/shadowops-infra/actions/runs/44795421159)
found Star Adventures staging project ownership correct, but no private Pages
policy, no app-only proof binding, no active Identity audience, and anonymous
game content available on the canonical host and current Pages aliases.

The tool scripts/staradvs_private_pages_policy.py configures **only** the
already-owned staradvs-staging Pages project. The default `plan` uses GET.
A separate, **manual-only** workflow_dispatch `apply`, after typing
`STARADVS_PRIVATE_PAGES_POLICY`, requires the protected staging environment,
exact Infra main SHA and the shared staging publisher concurrency group.
No push, schedule or PR can run `apply`.

The preflight refuses missing/foreign DNS, project, branch, domain, Pages alias,
a GitHub-attached foreign source, incompatible mode types, unsafe Cloudflare
compatibility flags and unexpected identity bindings. The PATCH includes
**only** deployment_configs.production/preview fail_open=false and sorted
compatibility flags containing global_fetch_strictly_public, preserving other
flags. A GET-only postflight verifies convergence, idempotence, and unchanged
binding *names and types*; neither the service credential value nor other
Cloudflare response body is logged. It does not update credentials, assets,
DNS, backups, Identity users or other Pages projects.

**Important:** changing `fail_open` does **not** encrypt or gate an existing
static Pages site by itself. Until the reviewed Worker is actually deployed,
and the `staradvs` audience and unique service binding are live, the already
public game and historic aliases may remain accessible. The automatic public
publisher remains paused by the independent protected-release contract.

Manual path in GitHub Actions:
1. Choose `Star Adventures · private Pages policy (manual only)` and operation
   `plan` to verify exact resource ownership without mutation.
2. When appropriate, choose `apply`, enter the exact confirmation text and
   pass staging environment approval. Review the `updated-private` (or
   `already-private`) receipt.
3. Run the separate read-only Identity readiness check again. Do not mark the
   game protected until anonymous denial and real signed-in E2E have passed.

There is no production action in this workflow.
