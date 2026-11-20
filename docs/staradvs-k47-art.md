# Star Adventures · K-47 original GLB publication

This is a **manual, two-stage** publication contract. It never deploys or
activates the game by itself. The source of truth is the *actual original GLB
binary bytes* and 390/1280 real Chromium screenshots produced by the
`evilsysadmin/star-adventures` source workflow
`.github/workflows/k47-sector-visual.yml`.

## Preconditions

1. The exact 40-hex Star Adventures source SHA is current `main`, with
   completed successful **push** CI (core and Chrome). This is independently
   checked by `scripts/staradvs_source_admission.py` *twice*.
2. The same SHA has a successful **push** workflow named
   `K-47 unified architecture · full-sector visual gate`. Its single
   unexpired source artifact `k47-three-building-sector-<sha>` has a GitHub
   Actions SHA-256 `digest`.
3. A human has inspected **before/after authentic play** in the source
   artifact at 390 and 1280, including the normal follow camera, overview,
   officer readability and full playable yard. Source CI proves correctness
   and screenshot existence, not artistic approval. Model geometry must be
   clearly closer to the approved mock, not merely different.
4. Provision exact-`star-adventures`-bucket-scoped R2 S3 create/read credentials in the Infra
   `staging` environment as `STARADVS_R2_ACCESS_KEY_ID` and
   `STARADVS_R2_SECRET_ACCESS_KEY`. Existing Infra
   `CLOUDFLARE_ACCOUNT_ID` must refer to the correct account. These are
   **not** Football, Pawn Action or Chronicles credentials, and they are
   **never** stored or available in the public source repo.

## Execution

In the Infra GitHub Actions UI, select
`Star Adventures · manual K-47 original GLB publication`.
The workflow automatically runs a **read-only art admission** job on
the publisher's PR/push events. It also runs when selecting manual
`action=plan`, without entering a protected environment or requiring
Cloudflare credentials. This job independently discovers the exact current
green source run/artifact, downloads the signed-digest ZIP, validates all
original GLB 2.0 chunks, canonical blocked footprints, full SHA-256/size,
exact source receipt and 8 real 390/1280 PNG screenshots. It records
`K47_READONLY_ART_ADMISSION_OK` and a source SHA in its summary.
**Audit/plan cannot write to R2.** An admission failure blocks the manual
publisher; fix the source artifact or credentials rather than bypassing it.

After visual inspection, run again with `action=publish`, the same current
source main SHA, and `confirm_reviewed=K47-VISUAL-APPROVED`. The Infra
`staging` environment review gate must be satisfied. Publication
creates only missing immutable keys under
`star-adventures/environment/` using atomic
`IfNoneMatch: *`; it never deletes/repoints another game's asset or
modifies DNS/Pages/OCI. A complete dedicated bucket inventory must fit the
7 GB guard and K-47's 48 MiB prefix budget. Existing matching keys are
byte-verified; mismatching keys fail closed. Public CDN GET must prove:
HTTP 200, pinned HTTPS URL, correct model/gltf-binary MIME,
immutable cache headers, staging CORS, and SHA-256-equal actual bytes.

Only then does the workflow emit
`staradvs-k47-original-glb-public-verified-<sha>` receipt with
`activationDone=false`.


## Dedicated R2 public endpoint (2026-11-20)

- **Bucket:** `star-adventures` (not `chess-studio-assets`).
- **Exact object key prefix:** `environment/` **inside that bucket**. The bucket name is NOT part of each object key.
- **Public base URL:** `https://pub-0e83bbe83562412182441ed82173d704.r2.dev/environment/`.
- The three original SHA-addressed GLBs were manually uploaded by the operator. That is **not** proof of public readability, valid metadata or a passing integrity audit. The next read-only `probe` must verify the exact bytes and HTTP headers before any game manifest activation. The live read-only check found the first exact-byte model at `environment/`, confirming that the legacy shared-bucket prefix must not be retained.
- Ensure every GLB has `Content-Type: model/gltf-binary` and `Cache-Control: public, max-age=31536000, immutable`, and the bucket CORS policy returns an `Access-Control-Allow-Origin` matching `https://staging.staradvs.shadowops.dpdns.org` (or `*`). The existing manual publisher's `publish` mode can only verify already uploaded matching objects; it must **never** overwrite a mismatching immutable object.
- The `r2.dev` endpoint is an interim public origin with Cloudflare-managed rate limits; later move to a dedicated custom domain in a separately verified migration. No DNS or production change is part of this PR.

## Operator: complete HTTP metadata for manually uploaded GLBs

Read-only Infra audit on source SHA `981a8e23d0ca9a4e1b9dff9a4939cb01a9a42f26`
confirmed all three exact original GLBs are publicly accessible under
`star-adventures/environment/`? **No:** that is the old shared-bucket form.
The **correct** bucket is `star-adventures`, object prefix `environment/`,
and public URL starts with `https://pub-0e83bbe83562412182441ed82173d704.r2.dev/environment/`.
The real audit reached all three files with valid MIME and SHA-matched bytes,
but found that **all three lack immutable Cache-Control and staging CORS**.

These are two different settings:

1. **Bucket-level CORS.** Cloudflare dashboard → R2 → `star-adventures` →
   Settings → CORS Policy → Add CORS policy → JSON. Use read-only origins and
   methods (no PUT, POST or DELETE):

   ```json
   [
     {
       "AllowedOrigins": [
         "https://staging.staradvs.shadowops.dpdns.org",
         "https://staradvs.shadowops.dpdns.org"
       ],
       "AllowedMethods": ["GET", "HEAD"],
       "AllowedHeaders": [],
       "MaxAgeSeconds": 3600
     }
   ]
   ```

   CORS is not proven by a plain HEAD without an `Origin` header. The
   existing Infra read-only probe sends the staging Origin and verifies
   the effective public response.

2. **Object HTTP metadata** for each of these existing exact objects:
   `environment/east-utilities-shell-14f64c52b6e92574.glb`,
   `environment/south-industrial-shell-903b06139f9f3881.glb`, and
   `environment/west-archive-shell-6620dd38f67fc22a.glb`.
   Keep `Content-Type: model/gltf-binary` and set
   `Cache-Control: public, max-age=31536000, immutable`. Change HTTP
   metadata with the R2 object controls if supported, or by an operator-
   authorized metadata replacement using the S3-compatible API.
   **Before any metadata rewrite, independently read and compare exact
   object bytes/size/SHA-256 to the approved source manifest**; never
   change model bytes or the content-addressed filenames.

After the settings propagate, re-run only the failed job of
`Star Adventures · manual K-47 original GLB publication` on the Infra PR
(or run a fresh read-only `plan` on Infra `main` after merging).
The output must be `K47_PUBLIC_CDN_BYTES_VERIFIED`, with a
`k47-public-cdn-bytes-<sourceSha>` artifact; a 200 alone is insufficient.
This is **not** authorization to activate the game until a separate
visually reviewed Star Adventures manifest PR passes.

## Activation is a distinct source PR

Use the **verified** receipt to update only the three
`content/scenes/k47-environment-art.json` slots in Star Adventures, pinning
the exact published URL, bytes, SHA-256, original provenance and unchanged
blocked footprint/anchor. That PR must undergo real 390/1280 game screenshots,
WebGL-denied fallback, fog, movement and F5; keep Draft until actual review.
The old SVG/3D placeholder is the rollback. Never mark a slot `published`
before live public HTTPS verification; never invent checksums/URLs.

This pipeline does not accept proprietary Star Trek models, unlicensed media,
unknown external GLB resources, screenshots substituted for source binaries,
untested source commits, outdated source `main`, or production activation
without a separate reviewed PR.


## Read-only live CDN readiness and activation handoff

Every K-47 source-art audit also verifies the **public CDN itself** using
the exact byte bodies and immutable keys from the admitted green
`star-adventures` source-main artifact. It has no Cloudflare or R2 keys and
cannot perform a write. A 404 is classified as `K47_PUBLIC_CDN_PENDING`
(expected before the approved upload). Redirects, inaccessible CDN, incorrect
MIME/CORS/cache headers, wrong lengths or wrong GLB bytes are NOT treated as
missing; the audit fails closed instead of claiming the art is published.

When and only when **all three** objects return approved headers and identical
model bytes, audit produces an artifact called
`k47-public-cdn-bytes-<source-sha>` containing `public-proof.json`.
The proof pins the current original-art source SHA, all three public HTTPS URLs,
full SHA-256, byte sizes and the matching `manifest` ready for review. The
fields `humanVisualApproval=false` and `activationDone=false` ensure this
isn't an automatic game release. If the CDN still returns any 404, no
public-proof artifact is produced; the audit reports the number missing.

The `probe` subcommand may also be run locally on the admitted source ZIP
with `--source-sha ... --artifact ... --out public-proof.json`; it neither
fetches untrusted URLs nor touches cloud credentials. After approval, a
**separate** game PR activates only the verified manifest and must run
real mobile/desktop gameplay, fog, F5, click targets and WebGL fallback.
