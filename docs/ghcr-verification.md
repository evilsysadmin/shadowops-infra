# GHCR image attestation gate

Uses the GitHub CLI to verify the immutable GHCR image digest against the trusted Chronicles repository and examines verified provenance for a source commit match. This is a **pre-deployment candidate gate**, not a deployer.

Before enabling live use, validate the attestation statement structure against a real Chronicles image produced by the approved build workflow; require exact workflow identity and provenance predicate type, not merely the repository; enforce artifact availability and permissions. An attestation cannot replace required CI checks or staging smoke evidence. The current mock tests do not prove that a real image exists.

No live deployment and no Chess Studio changes.
