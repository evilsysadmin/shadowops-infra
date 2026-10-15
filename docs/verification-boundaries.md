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
