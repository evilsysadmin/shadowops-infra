# Chronicles staging admission (read-only)

The command `scripts/check-staging-candidate.mjs` is an explicit, **read-only
pre-deployment gate**. It never invokes Docker, OCI, Render or Cloudflare and
never stores or changes secrets or game state.

Provide `GH_TOKEN` securely through an approved secret injector before\nrunning the command; do not paste the token into shell history.\n\nIt accepts only a SHA, an immutable image digest and the GitHub source
publication run ID. The repository, service, staging environment and dispatch
identity are fixed internally. Check names and source evidence cannot be
supplied by the calling process.

```sh
node scripts/check-staging-candidate.mjs \
  --sha 329b6b63244bd1dbe9d504d5a0340a78acf933bb \
  --digest sha256:3aa847cb86f7e29b1473c6ccaefdceddfcf8e1e5208fb25b84e82ce22f07bd50 \
  --run-id 38808611625
```

The example points to a **historically published** image. It is not a
recommendation to redeploy that revision; use the exact source/digest/run
being admitted instead. Set `GH_TOKEN` through an approved secret injector,
not directly in shell history. It needs read access to the Chronicles source
repository's runs, commits, checks and branch policy, plus package-attestation
verification access.

Successful accreditation requires, in order:

1. Correct staging candidate shape and fixed source identity.
2. A completed successful `main` push run from the stable publishing
   workflow ID and exact source SHA.
3. The source commit remains in current `main` ancestry, and `main`
   reports `protected: true`.
4. The **five fixed trusted checks** on that SHA completed successfully,
   including publication/policy checks from the verified run itself.
5. Sigstore-verified GHCR provenance enforces the signer workflow, source
   SHA, `refs/heads/main`, SLSA predicate type, and immutable image digest.

The command prints `STAGING_CANDIDATE_ACCREDITED` only when every gate
passes, otherwise returns nonzero with `STAGING_CANDIDATE_BLOCKED`. The
current Chronicles `main` branch reported **unprotected** on 2026-10-15,
so an otherwise valid real candidate should be **blocked** pending
[Chronicles #49](https://github.com/evilsysadmin/chronicles-of-matthias/issues/49).

**No deployment is triggered even on success.** Staging still needs an
approved OCI executor, host/secret provisioning, independent live smoke,
trusted receipt and rollback before any production promotion. This CLI
does not accept untrusted external `requiredContexts`, evidence JSON
or actor identity.
