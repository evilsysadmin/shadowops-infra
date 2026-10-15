# Chronicles deployment state machine

Candidate releases follow pending → accredited → deploying → verifying → healthy. Promotion and rollback are explicit transitions; failed and rejected states are terminal.

This is a pure transition policy, not an executor or audit log. The real controller must persist each transition with atomic compare-and-swap on version, enforce fencing tokens, derive authenticated actor from trusted runtime identity, and record evidence. Never trust a caller-provided actor. Production must independently validate staging receipt and digest.

No deploy or Chess Studio changes.
