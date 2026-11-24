# Star Adventures — ShadowOps ID staging cutover

Use the same authentication model as Football: ShadowOps ID and an advanced-mode Pages Worker. Cloudflare Access and Zero Trust are **not prerequisites**. The old anonymous publisher stays frozen (`pending-identity`).

## One-time cutover

1. Provision the isolated `staradvs` consumer in staging Identity Vault and deploy the updated Identity service. Verify the live login recognizes the audience.
2. Run the existing private Pages policy and isolated service-proof binding workflows. Both Pages modes must be fail-closed with strict public-origin routing; only production may contain the dedicated `SHADOWOPS_STARADVS_SERVICE_CREDENTIAL` secret-text binding.
3. Obtain the latest successful [protected candidate](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-candidate.yml) for the exact green game main SHA and current protected Infra paths.
4. Run [protected publisher](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-publish.yml) from main with `operation=preflight` and that candidate run ID. It checks owned Pages/DNS, live audience, proof binding and complete provider-reported history. No mutation.
5. Run the same publisher with `operation=publish` and confirmation `STARADVS_PUBLISH_AND_RETIRE_OLD_DEPLOYMENTS`. **This explicitly authorizes permanent removal of all preexisting deployments of the dedicated staradvs-staging project**, including old rollback versions. It does not delete the project, DNS, source, saves, other games or game production. This is a one-time cutover, not routine release retention.

The workflow captures a complete inventory before uploading the exact verified protected bundle. Only after the new canonical deployment matches the admitted source SHA and guest checks return 401 on the custom domain and 404 on the new Pages alias and base domain does it retire previously inventoried deployments. It rechecks the active canonical before every deletion; unknown or changed history blocks. No public rollback. Any provider rejection or partial cleanup fails the workflow; inspect the result and repair forward. Old anonymous aliases may remain reachable between upload and retirement, or if a deletion fails. Never claim protection until postflight independently verifies every recorded former alias and current routes (GET and HEAD on /, /index.html, /bridge, /release.json), with complete remaining inventory. Unlisted historical URLs cannot be certified. The old static publisher remains frozen.

## Acceptance

Guest denial is not signed-in acceptance. Test actual ShadowOps ID login, bridge, reload, assets, renewal, global logout, revocation, expiry and cross-audience denial on staging. Production is not promoted. No Access credentials are needed by this publisher. The old Access quarantine workflow is optional, not part of this cutover.

The candidate provenance, exact Worker/bundle checks, protected staging environment, source CI and Infra revision checks remain unchanged. Use the approved Pages token; Pages Write is required for deployment deletion. No new service or token family.
