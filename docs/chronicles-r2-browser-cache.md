# Chronicles R2 browser-cache readiness

Chronicles' six-pose goblin was uploaded to R2 bucket `chronicles`, key
`sprites/ash-goblin.webp`. The Cloudflare dashboard URL is **not** a public
asset origin. The game-side loader is in
[Chronicles PR #655](https://github.com/evilsysadmin/chronicles-of-matthias/pull/655).

`Chronicles R2 · public asset cache read-only probe` inspects Cloudflare's
custom-domain configuration for that exact bucket, then makes a public HTTPS
`HEAD` request with the staging `Origin`. It verifies MIME type, CORS and
the absence of a dangerous one-year immutable header on the **mutable** key.
The workflow makes **no mutations**. No S3 API keys are needed. A 403 from
Cloudflare means the existing Infra token lacks R2 read permission; it does
not establish that the bucket or public origin is absent.

To enable browser-cache reuse safely:

1. First establish an active, TLS-ready R2 **custom domain**, distinct from
   the private dashboard and from the rate-limited development `r2.dev` host.
2. Publish a reviewed, content-addressed sprite with a key like
   `sprites/ash-goblin-<sha16>.webp`; preserve the original and previous
   versions for rollback.
3. Return and verify `Cache-Control: public, max-age=31536000, immutable`
   **only** for immutable hashed assets. Never use that policy for unhashed
   sprite names, HTML, release JSON, manifests, user data, save APIs or
   mutable `current.*` aliases.
4. Prove real HTTPS `HEAD` headers and CORS on the versioned sprite, then
   prove that a second browser navigation avoids a network download while
   a changed version URL causes one fresh request.
5. Pin the verified public URL in the Chronicles asset manifest/build, test
   the real sprite in staging and keep the old version for rollback.

This probe is read-only inventory, **not** successful cache deployment.
