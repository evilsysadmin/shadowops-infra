# Chronicles portraits · manual R2 publication

The existing `chronicles` bucket and
`https://assets.chronicles.shadowops.dpdns.org` are owned by ShadowOps Infra.
This publisher only creates immutable WebP objects under `portraits/`.
It never updates the game's approved URL manifest, production, Pages, DNS,
cache rules, redirects, or existing objects.

**Source contract:** `chronicles-of-matthias` at the current `main` SHA,
with its three protected source CI workflows green, using the existing
`frontend/scripts/prepare-portrait-r2.mjs` to prepare exactly 24 canonical
**awake** WebPs and a checksummed manifest. No sleep variants are published
until they're faithfully edited and approved separately.

## Running

GitHub Actions → `Chronicles · controlled R2 portrait publication` → Run workflow,
from **shadowops-infra main**. Provide the full exact 40-character
Chronicles main SHA. First select **plan**: it checks SHA/CI, generates the
24 candidate files, and prints only aggregate counts. A plan never needs
Cloudflare secrets and never contacts R2.

For the explicit first publish, select **publish** and type exactly
`chronicles` in `confirm_bucket`. Only this operation creates objects.
The staging environment may apply repository approval controls. Publication
fails closed if GitHub source main or Infra main has changed, source CI
isn't green, the public custom domain isn't approved, credentials are absent,
prefix inventory is incomplete, existing contents differ, or the CDN cannot
serve the new immutable bytes correctly.

## Credentials

Use a **dedicated bucket-scoped S3 key pair** with permission limited to the
existing `chronicles` bucket, configured as staging environment secrets:
`CHRONICLES_R2_PORTRAIT_ACCESS_KEY_ID` and
`CHRONICLES_R2_PORTRAIT_SECRET_ACCESS_KEY`. The script cannot prove the
account-side IAM scope, so **configure and inspect it in Cloudflare** before
any publish operation. It does not accept a generic global Cloudflare
write token or fall back to the pre-existing read-only token.

The existing `CHRONICLES_R2_ACCOUNT_ID` and `CHRONICLES_R2_READ_TOKEN`
are required only for read-only validation of the approved active custom
domain. `GH_TOKEN` comes from the GitHub Actions read-only job token.

## Immutable / rollback guarantees

- Allowed keys are exactly
  `portraits/<one-of-24-ids>/awake-<sha256-prefix-16>.webp` in
  `chronicles`, up to 256 KiB/object, 4 MiB/batch and 32 MiB portrait prefix.
- The whole candidate and existing keys are verified before the first write.
  New uploads use conditional `IfNoneMatch: *` and are SHA-checked by R2
  readback and by the actual HTTPS CDN. Unexpected outcome stops the job;
  never retry a potentially ambiguous PUT blindly.
- The bucket must serve `Content-Type: image/webp`, CORS including the
  Chronicles staging origin, and `Cache-Control: public, max-age=31536000, immutable`.
- After success the workflow stores a **candidate** manifest artifact for
  14 days. A **separate review PR in Chronicles** activates approved public
  URLs. Never auto-push that manifest into the game.
- Local bundled originals remain a usable fallback in Chronicles. Old
  objects are not deleted while releases may still refer to them.

To add eyes-closed portraits later, review the *true* edited original art
and extend this publisher's allowlist/tests in another small PR. Previous
mockups or recropped UI screenshots are **not** canonical sources.
