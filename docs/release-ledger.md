# Release ledger / rollback policy

A bounded ledger records staging-accredited production releases and their exact immutable image digest. Rollback selection points to the preceding distinct digest, never a mutable tag.

This is **pure validation and target selection**, not trustworthy storage. A real deployment controller must write an append-only, authenticated ledger after verified deploy and smoke tests, with concurrency protection, monotonic sequence, audit trail, and rollback health checks. Do not accept arbitrary JSON from dispatch payloads or use this module as authorization to deploy.

No OCI, production, or Chess Studio changes.
