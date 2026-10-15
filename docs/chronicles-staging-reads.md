# Chronicles authenticated read API: staging opt-in

**Status:** configuration contract only. This change does not provision a server,
publish a container, transfer a save, create an account or deploy staging.

## Isolation and prerequisites

- Apply only on the dedicated OCI staging host. `compose.staging.yaml` uses
  the `shadowops-chronicles-staging` project; the baseline Compose project is
  `shadowops-chronicles`. Both publish the same loopback port, so **do not run
  them on the same host**.
- Use an attested, digest-pinned Chronicles API image that contains
  `chronicles-of-matthias` PR #45 or later, from a reviewed staging SHA.
- Supply a **staging-only** MongoDB URI via
  `CHRONICLES_MONGO_SECRET_FILE` and the explicitly isolated
  `CHRONICLES_MONGODB_DATABASE`. Staging must never point to a production
  database or Chess Studio production identity store.
- Supply a **different staging-only HS256 signing key** as an absolute
  file path in `CHRONICLES_STAGING_JWT_SECRET_FILE`. The mounted file must be
  a regular file, at least 32 bytes, readable by container UID 65532, and not
  checked into Git, printed by CI or included in generated artifacts.
- Provision synthetic `users` documents (`_id`, `session_version`) and
  `chronicles_runs` documents for smoke tests in the staging database.
  This does not migrate existing player identities or their saves.

## Deployment admission

Run on the dedicated staging host only, with the three required host-local
environment variables and a vetted `CHRONICLES_IMAGE_DIGEST` already set:

```sh
docker compose -f compose.yaml -f compose.staging.yaml config --quiet
docker compose -f compose.yaml -f compose.staging.yaml up -d
```

The normal deployment continues to use **only** `compose.yaml`; it does
not carry `CHRONICLES_ENABLE_READ_API` or any JWT secret and therefore
cannot accidentally expose the read routes.

## Acceptance and rollback

1. `GET /healthz` is 200 and `GET /readyz` is 200 when MongoDB is reachable.
2. Anonymous/expired/revoked session reads return 401. A user cannot read
   or list another user's runs.
3. An authorized test user can list a synthetic active expedition and
   retrieve its world flags, inventory and quests from MongoDB.
4. POST/PUT/DELETE run routes and bootstrap stay unavailable.
5. A down MongoDB or authentication store fails closed, with no private
   identifiers, credentials or database errors in the HTTP body.
6. Check the exact deployed image digest and source SHA; retain a previous
   digest for rollback. Do not use production credentials or real customer
   saves as smoke fixtures.

To disable read routes, deploy the original Compose baseline or remove the
staging overlay and redeploy a known-good digest. Do not destroy volumes
or alter MongoDB data while rolling back.

**Not yet solved:** browser CORS/auth flow, identity/save migration across
origins, full Python HTTP parity, gameplay writes/checkpoints and production
promotion. Passing this contract is not permission for production cutover.
