# Star Adventures · isolated ShadowOps ID service credential to Cloudflare Pages

The audited Star Adventures staging environment has a dedicated Pages project
`staradvs-staging` but the app-only secret
`SHADOWOPS_STARADVS_SERVICE_CREDENTIAL` is not yet bound. **Do not use**
another game's service proof, an operator bundle, a browser cookie, or any
ShadowOps ID signing key in Pages.

`scripts/staradvs_identity_binding.py plan` only GETs the exact Pages
project and reports whether the expected secret **name and type** exist.
The manual workflow defaults to this plan. It does not read Vault on plan
and does not claim that a pre-existing binding matches the current secret
value.

The protected, explicitly confirmed `bind` action:
1. Requires GitHub Infra `main` SHA unchanged, environment `staging`
   approval and the dedicated publisher concurrency group.
2. Requires exact Star Adventures project/DNS/domain ownership and both
   production + preview Pages configurations `fail_open=false`,
   `global_fetch_strictly_public`, and no foreign environment bindings.
3. Reads the **existing** validated operator staging bundle from OCI Vault,
   extracting only `consumers.staradvs`. It rejects unprovisioned or malformed
   application-specific proof. It does not provision, rotate, regenerate,
   print or export the operator bundle.
4. PATCHes only `deployment_configs.production.env_vars` with the single
   `secret_text` named `SHADOWOPS_STARADVS_SERVICE_CREDENTIAL`.
   Preview mode gets no service credentials. Reads back name/type and
   fail-closed policy without comparing or printing the secret value.
5. Writes no game source, Pages deployment, Cloudflare DNS, producer app,
   signing key, GitHub repo secret, or other game resources.

### Manual activation order

- First run the existing `ShadowOps Identity · isolated staging operational
  handoff` workflow with `action=provision` and
  `staradvs_consumer=enable`. Then deploy/verify the actual staging IdP
  audience using the separate authorized Identity release path.
- Apply the reviewed `Star Adventures · private Pages policy (manual only)`
  workflow, operation `apply`, after its GET-only `plan`.
- Run `Star Adventures · isolated Identity Pages credential (manual only)`
  with `operation=plan`; for `bind`, type
  `STARADVS_BIND_ISOLATED_IDENTITY` and pass staging approval.
- **Do not unpause the Pages static publisher.** It remains paused
  until a separately reviewed protected Worker deploy pipeline replaces
  public-200 verifier/browser checks with real guest-denial and signed-in
  E2E, including historical aliases, token expiry/revocation and rollback.
- Only describe the game as protected after that live verification.
  A secret bound into Pages but no deployed Worker protects nothing by itself.

This workflow has no scheduled or automatic binding action.
