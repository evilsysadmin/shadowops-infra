# Safe rollout sequence

1. Build and test a standalone Chronicles Go binary; implement its healthcheck command before running this Compose.
2. Publish its image to GHCR, pin by sha256 digest and attest the source commit.
3. Independently verify provenance and staging eligibility before setting CHRONICLES_IMAGE_DIGEST.
4. Configure host-local ingress, secret injection and data connections. Do not expose container ports publicly.
5. Deploy Chronicles only; run health, F5, saves, authentication and gameplay smoke tests.
6. Introduce release accreditation, production approvals and digest rollback before enabling automated deploys.

**Not deployed:** This initial Compose is a reviewed runtime contract, not proof of a built image or working healthcheck. No OCI or Cloudflare changes are made. Chess Studio remains outside scope.
