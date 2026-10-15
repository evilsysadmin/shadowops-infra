# Chronicles admission orchestrator (dry-run only)

Combines payload shape validation, independent GitHub source-run evidence, required check runs, GHCR attestation verification and final candidate accreditation. This is **not a deployment workflow**.

Security blockers before enabling any real release: source workflow must exist and be authenticated by stable ID; source SHA must belong to protected main history; check identities must come from authoritative branch rules and trusted apps; attestation provenance must be checked against actual signed GHCR image and expected workflow; dispatch actorRepository cannot be trusted unless independently derived. No caller-controlled evidence or requiredContexts may be accepted by a privileged controller. Add a production-grade evidence collector and integration tests against real artifacts before enabling.

No Chess Studio changes.
