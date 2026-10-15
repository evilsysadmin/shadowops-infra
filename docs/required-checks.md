# Trusted source checks gate

The release admission controller **does not accept check names from the
release dispatch payload**. It requires all five fixed Chronicles jobs,
observed directly in GitHub's check-runs API for the exact candidate commit:

- `repository-contract` — independent Chronicles repository contract
- `build-and-test` — Go unit and MongoDB integration tests
- `smoke` — non-root Go container smoke
- `staging-image-policy` — source image-publish policy
- `publish-staging-image` — actual source build, GHCR push and attestation

Every check must be unique, successful, completed, report the exact source
SHA, belong to the trusted GitHub Actions app, and link back to an Actions
job in `evilsysadmin/chronicles-of-matthias`. The two publication jobs
must belong to the **same independently verified source workflow run** that
is being accredited. Ambiguity, pagination or an untrusted app fail closed.

The live GHCR verification workflow also queries these **historical** check
runs against the real source SHA `329b6b63244bd1dbe9d504d5a0340a78acf933bb`
and workflow run `38808611625`. This is an evidence fixture, not an
automatic promotion decision. Real release admission must always query the
candidate's own current check runs.

**Still required for actual deployment:** configure and verify protected
`main` with authoritative branch rules and required trusted checks; preserve
main ancestry, signed GHCR provenance, the exact verified build digest and
staging health/smoke gates. This policy does not itself configure GitHub
branch protection. No deployment is enabled here.
