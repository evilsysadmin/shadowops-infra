# Accreditation gate: evidence interface

This module evaluates an evidence record only. It does **not** fetch evidence from GitHub or GHCR, and therefore must not be called with caller-provided assertions in a deployment workflow.

Next integration must independently obtain workflow run and commit from GitHub API, verify the successful protected-main publishing workflow, verify required checks, and cryptographically verify the GHCR attestation linking the immutable image digest to the source SHA. Construct evidence exclusively from those verified sources.

A separate staging deployment receipt (digest, run, health and smoke status) is required before any production promotion. No live dispatch receiver or deployment workflow is installed by this PR.
