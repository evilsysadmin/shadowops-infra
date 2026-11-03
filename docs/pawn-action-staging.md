# Pawn Action — dedicated staging domain (pre-publication)

The staging URL agreed for Pawn Action is:

**https://staging.pawnaction.shadowops.dpdns.org/**

This is a subdomain of the existing **shadowops.dpdns.org** Cloudflare zone.
Do not use the misspelled zone shadwops.dpns.org.

## Ownership and isolation

| Resource | Intended owner or value |
| --- | --- |
| Source / Godot Web artifact | evilsysadmin/pawn-action |
| Staging Pages project | pawn-action-staging |
| Dedicated staging DNS | staging.pawnaction.shadowops.dpdns.org |
| Current production legacy Web pointer | Chess Studio owns pawn-slug-godot/current.json |
| New immutable release namespace | pawn-action/releases/<sha256-prefix>/ |
| New mutable release pointer | pawn-action/current.json |
| DNS / Pages / R2 deployment credentials | evilsysadmin/shadowops-infra only |

The current Pawn Action extraction is still a draft. This document and its
read-only inventory are **not evidence that the Pages project, DNS entry,
server-side authentication, release artifacts or public URL exist**.

## Safe next steps

1. Run the offline tests in the PR. Once merged, manually dispatch the
   "Pawn Action · staging Pages DNS preflight" workflow on Infra main.
   It reads existing zone, Pages project, custom domain and DNS; absent
   resources are reported as absent. Any foreign or ambiguous ownership
   fails closed. It never creates or edits resources.
2. Admit a full current Pawn Action `main` SHA using the read-only
   `pawn-action-source-admission.yml` workflow. It requires a green `push`
   Godot CI run with the real Chromium input/lifecycle step (never skipped)
   and two unique, non-expired SHA256-bound GitHub artifacts. A Draft PR,
   green PR-only result or missing visual artifact cannot authorize a release.
3. Establish the staging access policy and apply an appropriate server-side
   access gate before public delivery. Do not imply that a browser-only
   JavaScript flag is authentication.
4. Provision the dedicated Pages project/domain from Infra only after
   ownership and access policies are accepted. Keep the legacy Chess Studio
   version and pointer untouched for rollback.
5. Publish only the new pawn-action/ namespace using bounded R2 credentials,
   verify HTTP/TLS, CORS, browser WASM, game input, exact source SHA, and
   rollback before switching the Chess Studio launcher.

Do not reuse the Football, Star Adventures or Chess Studio Pages projects,
DNS records or mutable release pointers. No additional VM or automatic
promotion to production is authorized by this staging-domain contract.

## Exact-source Web artifact admission (no cloud writes)

After Pawn Action #1 is approved and merged, its **main** CI must pass the
same Godot, keyboard/touch and browser gates as the PR, then upload
`pawn-action-godot-web` and `pawn-action-real-visual-evidence`.
Infra reads only the source GitHub API and refuses an obsolete or non-main SHA.

Manual read-only check (with GH_TOKEN):

```sh
python3 scripts/pawn_action_source_admission.py check <full-current-main-sha>
python3 scripts/pawn_action_source_admission.py verify-archive ./pawn-action-godot-web.zip sha256:<actions-artifact-digest>
```

The ZIP must come from the **admitted run's exact artifact ID**. The byte
digest, entry CRC, file bounds, safe paths and required Godot HTML/JS/WASM/PCK
are verified before any extraction. Recheck the source SHA immediately before
any future Cloudflare mutation; admission is not a distributed deploy lock.

The workflow has no Cloudflare credentials, and **never** creates Pages/DNS,
uploads R2, modifies Chess Studio's legacy pointer, authenticates users or
publishes staging. Release permission, server-side access policy and actual
staging verification remain separate later gates.

## Offline R2 release candidate (no deployment)

The actual Godot Web ZIP can contain a 39.5 MB `index.wasm` and therefore
**must not** be shipped directly as a Cloudflare Pages static file (25 MiB
per-file limit). Stage the large immutable payloads separately in R2.
The future Pages host and server-side authentication gate are not in this
package and must be validated separately.

After exact-main CI admission, download the Web ZIP by the **admitted run and
artifact ID** and verify its **Actions digest**. Prepare the same source bytes
without re-exporting/rebuilding Godot:

```sh
python3 scripts/pawn_action_web_package.py prepare \
  --zip ./pawn-action-web.zip \
  --digest sha256:<admitted-actions-zip-digest> \
  --source-sha <admitted-40-hex-main-sha> \
  --run-id <admitted-run-id> \
  --artifact-id <admitted-artifact-id> \
  --out ./pawn-action-candidate
python3 scripts/pawn_action_web_package.py validate \
  --out ./pawn-action-candidate \
  --source-sha <admitted-40-hex-main-sha>
```

The output is an immutable `runtime/` tree and deterministic
`release.json`. The release digest uses **the same filenames, SHA256 hashes
and file-size hashing algorithm as Pawn Action's Godot bundle publisher**.
Each manifest entry fixes the SHA256, exact size, content type and intended
`pawn-action/releases/<release-id>/...` R2 URL. Oversized Pages assets
are enumerated explicitly. It records the originating CI run, artifact ID
and archive digest as supplied by the admitted source receipt.

This package is **a candidate, not a deployment**: `publishAuthorized=false`,
no `current.json` or public Pages host is generated, and no Cloudflare
credentials are needed. The R2 prefix and legacy pointer remain unchanged.
Before any subsequent live publish, Infra must revalidate the source receipt,
the contents, the storage budget, Cloudflare ownership, access policy and
public HTTPS/browser runtime on the agreed staging hostname.

## Create-once R2 upload, manual gate only

`scripts/pawn_action_r2_immutable.py` is an operator-only uploader for the
existing `chess-studio-assets` bucket. It writes **exclusively** keys under
`pawn-action/releases/<content-digest>/`, never `pawn-action/current.json`
or Chess Studio's `pawn-slug-godot/current.json`. It never deletes assets,
creates buckets or changes DNS/Pages/production.

Cloudflare documents atomic **S3-compatible** `PutObject` writes with
`If-None-Match: *`. The uploader uses that create-once condition rather
than relying on a non-atomic list-then-PUT with the legacy REST API. It reads
the **whole shared bucket inventory**, fails closed on malformed/truncated
results and enforces strict byte limits: 7,000,000,000 bytes total projected
and 536,870,912 bytes under `pawn-action/`; there is no capacity override.
Existing immutable keys must match the manifest's exact size and SHA-256
before any writes. Every newly uploaded object is read back and verified.
Conflicting concurrent writes never overwrite the pre-existing object.

Preview a verified offline release, without dependencies, credentials or
network access:

```sh
python3 scripts/pawn_action_r2_immutable.py plan \
  --candidate ./pawn-action-candidate \
  --source-sha <admitted-current-main-sha>
```

Actual object upload is a **separate, manual-only future operation**. It
requires `boto3`, `GH_TOKEN` with source Actions access, Cloudflare account
ID, and dedicated **bucket-scoped S3** credentials in Infra operator custody
(`PAWN_ACTION_R2_ACCESS_KEY_ID`, `PAWN_ACTION_R2_SECRET_ACCESS_KEY`).
Before opening R2, the command rechecks the exact source main SHA and green
main browser CI + both artifact digests. It additionally requires the exact
`--confirm-immutable-upload pawn-action/releases/<content-digest>` flag.

```sh
python3 scripts/pawn_action_r2_immutable.py apply \
  --candidate ./pawn-action-candidate \
  --source-sha <admitted-current-main-sha> \
  --confirm-immutable-upload pawn-action/releases/<content-digest>
```

**No workflow runs `apply`, and this contract does not authorize running
it yet.** Bucket-scoped S3 keys still have broader bucket access than a
per-object prefix: the CLI restricts its own keys, but actual least privilege
also depends on how Cloudflare credentials are provisioned and kept in Infra.
No dedicated R2 credentials have been provisioned by these code changes.
The inventory-based capacity gate is a preflight, not a global lock against
other unrelated publishers; keep publication serialized by the Infra owner.
Server-side access policy, CDN checks, own Pages staging host, mutable pointer
ownership and rollback remain separate future gates.
