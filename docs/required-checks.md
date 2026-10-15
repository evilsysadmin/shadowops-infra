# Required checks gate

The gate fetches check runs for an exact Chronicles commit and fails closed if configured contexts are missing, unsuccessful, ambiguous or truncated. It is not a replacement for reading the authoritative GitHub branch ruleset/required-status-check configuration. Do not choose requiredContexts from caller input.

Before enabling deployment: derive and pin required check identities from branch rulesets, verify each trusted app/workflow identity, handle check-suite reruns/pagination, and validate the SHA belongs to protected main history. GHCR attestation verification remains mandatory. No deploy is enabled.
