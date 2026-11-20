# Chronicles staging — one-time immutable Pages preview Access pilot

**Context:** the historical Pages guest audit sampled 26 Chronicles staging
Pages hostnames returning anonymous HTTP 200. A 200 can be a public login
shell, so do not describe it as a gameplay breach without examining content.
Cloudflare documents that preview protection and the base Pages alias are
**different** from the game's custom-domain ShadowOps ID experience.

This is a **manual-only, staging-only, narrowly scoped opt-in operator action**
to create an Access self-hosted application for exactly
`*.chronicles-staging.pages.dev`. It is a limited pilot, **not** the entire
Pages hardening or a ShadowOps ID login migration.

Official provider references:
- https://developers.cloudflare.com/pages/configuration/preview-deployments/
- https://developers.cloudflare.com/pages/platform/known-issues/
- https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/create/

## Minimum credentials in GitHub's protected staging environment

Store these values as protected GitHub environment secrets, not in the repo,
workflow inputs, CI artifacts, browser, or chat:

- `CLOUDFLARE_ACCOUNT_ID`: the existing exact account identifier.
- `CLOUDFLARE_API_TOKEN`: the existing Pages GET token for project owner
  verification. The script never issues a Pages write.
- `CLOUDFLARE_ACCESS_READ_TOKEN`: independent `Access: Apps and Policies Read`
  permission, used by the default `plan` and postflight GET checks.
- `CLOUDFLARE_ACCESS_WRITE_TOKEN`: separate Access Apps and Policies Write
  token, used **only** for the manually confirmed `apply` job.
- `CLOUDFLARE_ACCESS_OPERATOR_EMAIL`: one explicitly named operator who
  must already be able to authenticate with a configured Access identity
  provider. Do not use `*@domain`, Everyone, IP ranges, or shared groups.

No write token or operator email may be passed in `workflow_dispatch` inputs.

## Controlled run

1. Open the
   [Chronicles staging Access pilot workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/chronicles-staging-access-preview.yml)
   on the exact reviewed Infra `main` branch. Select `operation=plan`
   (the default). Inspect the status. Missing secrets, foreign ownership
   or an overlapping Access app prevent mutation. The plan inspects
   raw hostname declarations before normalized API parsing; an invalid
   destination cannot conceal an already-covered staging wildcard,
   and broad `*.pages.dev` rules also block automatic creation.
2. Check that the existing canonical staging login and game remain
   accessible before applying. No Pages/OCI deploy may be in progress.
3. To apply **only on staging previews**, select `operation=apply` and type
   `CHRONICLES_STAGING_PREVIEW_ACCESS`. The job requires protected
   `staging` approval and enforces the same staging Pages deployment
   concurrency lock. It checks Infra main SHA twice before the POST.
4. The script creates **at most one** self-hosted Access application with
   exact `domain=*.chronicles-staging.pages.dev`, no app launcher entry,
   1-hour Access session and a single `Allow` policy for the one operator
   email from the staging environment. It never updates or takes over a
   foreign Access app, and never modifies existing policies.
5. The job re-reads the application/policy. On an ambiguous network or
   provider failure, do not retry POST without another successful plan.
   After creation, inspect recent immutable preview aliases externally:
   they should challenge guests rather than serve application assets.
6. Run the
   [historical Pages audit](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/game-identity-pages-history.yml).
   Inspect counts only; exact opaque deployment hostnames remain omitted
   from public logs. Verify the allowed operator can sign in, and that
   unrelated anonymous guests cannot fetch HTML/JS/manifest.
7. **Still not complete:** `chronicles-staging.pages.dev` root is not
   protected by the preview wildcard, and neither is the canonical custom
   hostname. Protect their separate Access scopes using the documented
   dashboard method, then verify ShadowOps ID, game API isolation,
   revocation and existing sessions. This pilot intentionally changes
   neither. Only then consider the reviewed production rollout.

### Recovery and state ownership

If the operator cannot reach previews after applying, inspect Access
settings through the authenticated dashboard and revert the **exact single
new application** after checking it is the one created by this pilot.
Do not delete Pages deployments, change DNS, disable game authentication,
edit production Access applications or blindly replay the write operation.

This GitHub PR **only installs the script and manual workflow**. It does
not create an Access application when merged. The CLI's response
`created-pending-guest-probe` means only Cloudflare acknowledged the
creation request; it is not a live security receipt.
