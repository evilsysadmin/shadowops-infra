# Verified GitHub evidence — incomplete accreditation

The verifier queries GitHub API for the exact source workflow run, source commit and branch protection. It does not accept workflow run metadata supplied by the dispatch sender.

**Remaining mandatory checks before deployment:** validate workflow identity by stable workflow ID and exact path (not display name), verify commit belongs to the protected main history and the required checks for that SHA, and verify the GHCR artifact digest plus cryptographic attestation. No live deploy may use this partial evidence as complete accreditation. GitHub API token must have least-privilege read permissions for the source repository.

No Chess Studio changes.
