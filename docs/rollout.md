# Safe rollout sequence

1. Build and test a standalone Chronicles Go binary; implement its healthcheck command before running this Compose.
2. Publish its image to GHCR, pin by sha256 digest and attest the source commit.
3. Independently verify provenance and staging eligibility before setting CHRONICLES_IMAGE_DIGEST.
4. Provision a Chronicles-only MongoDB identity and database, plus a host-local secret file containing its connection URI. Set CHRONICLES_MONGO_SECRET_FILE to that absolute file path and CHRONICLES_MONGODB_DATABASE to the database name. Because this Compose uses a file-backed secret and the container runs as UID 65532, verify the mounted file is readable by that UID without making it broadly readable on the host (for example, dedicated ownership and mode 0400). Never commit or print the URI. Do not expose container ports publicly.
5. Deploy Chronicles only. The container healthcheck invokes readycheck, requiring /readyz = 200 and a working MongoDB ping. A missing or broken Mongo connection MUST block a healthy deployment; /healthz is liveness only. Run F5, saves, authentication and gameplay smoke tests separately after the full API is implemented.
6. Introduce release accreditation, production approvals and digest rollback before enabling automated deploys.

**Not deployed:** This initial Compose is a reviewed runtime contract, not proof of a built image or working healthcheck. No OCI or Cloudflare changes are made. Chess Studio remains outside scope.

The MongoDB secret integration requires Chronicles API PR #37 (CHRONICLES_MONGODB_URI_FILE) and the readycheck CLI from PR #36. This repository does not create the credential, database, OCI instance or Cloudflare resources. Production cutover remains blocked until run API parity and save migrations are tested.
