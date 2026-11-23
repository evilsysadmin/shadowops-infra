# Star Adventures — reviewed private Pages release (operator only)

The game does **not** yet run behind ShadowOps ID. The existing
`staradvs-pages-staging.yml` static/public-200 publisher remains frozen by
`config/staradvs-protected-release.json` (`pending-identity`).

The new **separate**, manual-only
[protected Pages publishing action](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-publish.yml)
is an operator-controlled way to deploy a prebuilt approved game + exact
Infra-owned advanced-mode `_worker.js` after independent Cloudflare Access,
Pages policy, and Identity checks. It cannot publish from a PR or scheduler.

## Before running

1. **Quarantine** all historical, preview, primary Pages and custom-domain
   staging URLs using the separate
   [Access quarantine workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-access-quarantine.yml).
   Set its dedicated Access write token on the protected staging environment
   and run `plan` then approved `apply`. Cloudflare Pages preview policy
   enablement may require additional provider UI work. Never assume an API
   200 means enforcement is live.
2. Provision the dedicated `staradvs` consumer in the staging Identity
   operator Vault, **deploy the updated identity service** and independently
   prove that its real login recognizes the audience. Merely updating Vault
   does not activate a container.
3. Run the existing manual private Pages policy `plan/apply` and isolated
   service proof binding `plan/bind`. This must produce
   `fail_open=false`, the strict public-origin flag and a `secret_text`
   binding named `SHADOWOPS_STARADVS_SERVICE_CREDENTIAL` in the Pages
   **production** configuration only. Other games' credentials are forbidden.
4. Configure a **read-only** Cloudflare Access Apps/Policies token in
   `shadowops-infra` protected GitHub `staging` environment secret
   `CLOUDFLARE_ACCESS_READ_TOKEN`. Keep it separate from the Pages token
   and from the Access write token.
5. Run the nonmutating
   [protected candidate builder](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-candidate.yml)
   on the current Infra `main`. It validates the exact current green game
   SHA and creates `staradvs-protected-candidate-<game SHA>` with the
   correct `release.json` and exact reviewed `_worker.js`. Copy its
   numeric GitHub Actions **run ID**, never a user-supplied zip or token.
   Candidate artifacts expire after 7 days.

## Running the separate release

An unrelated Infra merge (Chronicles, Football or generic CI) no longer
invalidates a correctly built candidate. If its source Infra commit differs
from current `main`, the admission downloads both **complete, nontruncated
Git trees** and compares immutable blob IDs for **every** protected Star
Adventures path (Worker, release scripts/configuration, workflows and tests).
Any changed, missing, malformed, unverified or truncated tree blocks the
release; the artifact's own recorded `head_sha` must still match its run.
This reuses `scripts/staradvs_infra_revision.py` rather than weakening the
staging policy, and avoids recompilation for unrelated main changes.


Launch [the manual protected publisher](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-publish.yml)
on `main` with the candidate run ID and operation `preflight`. Its
first job authenticates to GitHub only to verify that the artifact
belongs to a completed successful trusted-main protected-candidate workflow,
on Infra **main**, for the exact current
green `star-adventures/main` SHA. It rejects ambiguous, duplicated,
expired or mismatched artifacts.

Its second job makes GET-only Cloudflare/Identity checks and requires:
- Ownership of the exact `staradvs-staging` Pages project, its proxied
  DNS name and custom domain.
- All three exact Cloudflare Access scopes with narrow policies.
- Provider-reported historical Pages inventory fully enumerated; a
  **mandatory independent HTTPS probe** on /, /index.html, /bridge and
  /release.json for every historical/current alias and the canonical host.
  The second scan must agree with the initial 404/401 denial verdict or
  independently verify the exact Access login challenge. No anonymous
  content, inconsistent route response or absent second scan is accepted.
- The live Identity `staradvs` login audience, fail-closed Pages policy
  and the dedicated isolated Pages secret-text binding.

Only after the above succeeds, launch the **same action from the same
Infra main SHA** with `publish`, the candidate run ID, protected
staging approval and confirmation `STARADVS_PUBLISH_PROTECTED_WORKER`.
It downloads only that exact artifact, verifies JS digest, Worker bytes
and release metadata, rechecks source and Infra SHAs, revisits all
Cloudflare gates, and only then invokes pinned Wrangler to deploy that
private package to the existing *staging* Pages project.

The workflow doesn't create/modify DNS, Identity, Access policies,
production or other games. No frontend build happens in the secret-bearing
publication job. The pinned Wrangler CLI is now installed and checked in a
**separate, token-free step** before any Cloudflare credential is injected
into the deploy step; Wrangler runs from the already installed local binary,
not through `npx` with Cloudflare secrets in its environment.

A `publish` operation with missing/wrong
`STARADVS_PUBLISH_PROTECTED_WORKER` confirmation **fails the entire workflow**
during artifact admission. It no longer produces an apparently successful
preflight-only run because the publishing job was silently skipped. A
`preflight` request must not include publication confirmation.

After uploading, the workflow retries the guest quarantine scan and
fails if exposed or ambiguous. **Never automatically roll back to the
old publicly accessible deployment.** Existing protective Access
policies stay in place even on postflight failure. Investigate and
repair forward, or use an independently approved protected rollback.

## Remaining acceptance after a successful upload

This is deliberately only a **candidate protected staging upload**,
not a verified player journey. An Access login `302` can be imitated
by an origin and cannot prove real ShadowOps ID authentication. It
remains mandatory to test an authorized user through Cloudflare Access
and ShadowOps ID, /bridge navigation, F5, assets, logout, revocation,
expired tokens, wrong audience, and existing old aliases. Verify the
published SHA and Worker from an authenticated browser. The old static
publisher stays blocked and no production promotion is triggered.

The protected release workflow emits no `STARADVS_STAGING_PUBLIC_READY`
and never sets `can_activate=true`. A green PR or candidate artifact
does **not** mean the live Cloudflare Pages app has been changed.
