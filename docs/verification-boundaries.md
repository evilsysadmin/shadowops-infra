# Verified GitHub evidence — incomplete accreditation

The verifier queries GitHub API for the exact source workflow run, source commit and branch protection. It does not accept workflow run metadata supplied by the dispatch sender.

**Remaining mandatory checks before deployment:** validate workflow identity by stable workflow ID and exact path (not display name), verify commit belongs to the protected main history and the required checks for that SHA, and verify the GHCR artifact digest plus cryptographic attestation. No live deploy may use this partial evidence as complete accreditation. GitHub API token must have least-privilege read permissions for the source repository.

No Chess Studio changes.

## Concrete source workflow admission (October 2026)

The published Chronicles staging image is produced by
`.github/workflows/staging-image.yml` (GitHub workflow ID `386009048`),
not the historical `publish-chronicles.yml` placeholder. Admission now
matches the authoritative run's path, stable workflow ID, source repository,
full commit SHA and completed successful push to `main`. It also queries the
GitHub compare endpoint and rejects source commits no longer ancestors of
`main`, while retaining the existing requirement that GitHub reports
`main.protected === true`.

**Current external blocker:** at the time this contract was corrected,
GitHub reported `main.protected: false` for the Chronicles repository.
This is not a reason to relax validation. Configure a real branch protection
rule (including required trusted CI checks and prevention of bypasses) in
repository settings before treating any candidate as admissible.

The first independently verified GHCR publication used commit
`329b6b63244bd1dbe9d504d5a0340a78acf933bb` from source workflow
run `38808611625`, digest
`sha256:3aa847cb86f7e29b1473c6ccaefdceddfcf8e1e5208fb25b84e82ce22f07bd50`
and GitHub attestation `56438420`. These are historical evidence pointers,
**not an automatic deployment decision or a permanent current image pin**.
Actual release admission must query current GitHub evidence, verify signed
provenance and pass the independent gates.


## Diagnosing a ruleset that looks active but does not protect main

The read-only diagnostic `node scripts/inspect-main-protection.mjs` queries
GitHub's branch API, lists active repository rulesets, and fetches their full
conditions and required check definitions. It exits nonzero unless `main` is
reported protected and an active rule targets `main` with PR merging, no
force-push/deletion, and the four **PR-available** checks:
`repository-contract`, `build-and-test`, `smoke`, and
`staging-image-policy`. The post-merge publication job is deliberately not
a required PR check. The script does **not** change GitHub settings.

The initial `Protect main` rule (ID `25198769`) was active, but inspection
on October 15 found both `conditions.ref_name.include: []` and
`required_status_checks: []`, while `main.protected` remained false.
Fix it in
[the Chronicles rule editor](https://github.com/evilsysadmin/chronicles-of-matthias/rules/25198769):
set target to default branch (`~DEFAULT_BRANCH`) and select the four check
contexts above. This user-facing GitHub action is required before the
admission controller will accept a release.

This is a supplementary configuration diagnostic, **not a substitute** for
the existing independently authenticated release admission chain. It does
not sign a receipt or deploy an OCI artifact.
