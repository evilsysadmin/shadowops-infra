# Chronicles media: controlled R2 copy and manual cutover

The standalone Chronicles game still loads two recorded-score MP3 files and two
Tactics party objects from the Chess Studio asset hostname. These four objects
are pinned by full SHA-256 hashes and lengths in the game manifest. Total:
12,793,710 bytes. They are *not* embedded in this repository.

## Workflow

1. Select the current main SHA in evilsysadmin/chronicles-of-matthias. Confirm
   Chronicles CI, Chronicles frontend and Chronicles API are green for that SHA.
2. Run GitHub Actions: "Chronicles · controlled R2 media copy" from
   shadowops-infra main with action=plan and the exact source_sha. This step
   reads the four source objects from the public Chess Studio CDN, verifies their
   pinned SHA-256 and sizes, and performs ZERO R2 writes or provider reads.
3. Only after source hashes are confirmed, configure dedicated bucket-scoped
   CHRONICLES_R2_MEDIA_ACCESS_KEY_ID and CHRONICLES_R2_MEDIA_SECRET_ACCESS_KEY
   as protected staging environment secrets. Configure these in Cloudflare with
   access restricted to the existing chronicles R2 bucket. The publisher cannot
   independently verify the provider-side effective IAM scope.
   Reuse neither Chess Studio nor portrait publication write credentials.
4. Explicitly select action=publish, confirm_bucket=chronicles and that same
   current source SHA. The staging environment may require approval.
   CHRONICLES_R2_ACCOUNT_ID and CHRONICLES_R2_READ_TOKEN are only for verifying
   the active Chronicles custom domain; GH_TOKEN reads the source CI status.
5. Before any upload, the program requires current source main plus green CI,
   an approved CDN domain, complete dedicated-prefix inventory, and byte-exact
   readback of any previously existing target. Unknown objects or collisions
   stop the batch. The source gate is rechecked immediately before new writes.
6. Every new object uses IfNoneMatch=* with the expected MIME and browser-cache
   policy. Readback from R2 and full public CDN SHA-256 must match. Uncertain
   uploads stop; do not blindly retry. Idempotent future runs reuse only exact
   copies. No deletions or overwrites are implemented.
7. Only after all four target objects pass the public CDN SHA proof, a
   successful publish uploads `chronicles-media-r2-candidate.json` as a
   **candidate artifact**. Its exact JSON shape matches
   `frontend/src/assets/r2-assets-manifest.json` in Chronicles: the same
   four logical IDs, keys, sizes, SHA-256 and MIME types, with the four URLs
   and `baseUrl` switched together to the dedicated Chronicles R2 hostname.
   The publisher does **not** commit or activate it.
8. Download that exact candidate artifact only from a verified successful
   publish workflow run. Independently review its full diff against the source
   manifest: only the five hostname values may change (four URLs and baseUrl).
   Apply it in a SEPARATE Chronicles source PR. Verify actual MP3 playback,
   mute, transitions and the Tactics GLB in a browser before approving.
   A green publication workflow is not evidence of gameplay compatibility.

## Safety and scope

The four allowlisted keys are all under the chronicles/ prefix of the chronicles
bucket, with a 24 MB prefix byte budget. Existing sprites and portraits are
outside that prefix and cannot be modified by the script. The script cannot
enforce Cloudflare IAM permissions; inspect those before publication.

No scheduled or PR-triggered upload: PR and push run offline tests only.
Plan is read-only. Publish requires manual dispatch, matching source/main SHA,
dedicated credentials, a protected staging job and confirmation.

The existing "Chronicles · media R2 public cutover proof" workflow can recheck
all four target objects independently with no Cloudflare credentials.

Merging this workflow neither publishes these assets nor deploys Chronicles.
