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
4. Provision exact-bucket-scoped R2 S3 create/read credentials in the Infra
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
`chess-studio-assets/star-adventures/environment/` using atomic
`IfNoneMatch: *`; it never deletes/repoints another game's asset or
modifies DNS/Pages/OCI. A complete shared bucket inventory must fit the
7 GB guard and K-47's 48 MiB prefix budget. Existing matching keys are
byte-verified; mismatching keys fail closed. Public CDN GET must prove:
HTTP 200, pinned HTTPS URL, correct model/gltf-binary MIME,
immutable cache headers, staging CORS, and SHA-256-equal actual bytes.

Only then does the workflow emit
`staradvs-k47-original-glb-public-verified-<sha>` receipt with
`activationDone=false`.

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
