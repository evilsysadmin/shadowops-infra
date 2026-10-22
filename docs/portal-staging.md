# ShadowOps Universe · staging Pages and DNS

- **Owner**: `evilsysadmin/shadowops-infra` exclusively.
- **Planned staging FQDN**: https://staging.shadowops.dpdns.org
- **Dedicated Pages project**: `shadowops-universe-staging` / `shadowops-universe-staging.pages.dev`
- **Do not claim live** until trusted-`main` release workflow prints `SHADOWOPS_UNIVERSE_STAGING_PUBLIC_READY` after public TLS, real HTML and JS, immutable SHA and six GLB fetch/checksum checks.
- GitHub staging environment must contain existing Infra-only `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Cloudflare token needs scoped Pages:Edit, Zone DNS:Edit, Zone:Read for `shadowops.dpdns.org` and account Pages project access. No credentials in PR jobs.
- The script refuses foreign or ambiguous staging DNS records, projects and custom domains. It never edits production `shadowops.dpdns.org`, Chess Studio, Chronicles, Star Adventures or the OCI tunnel.
- A pull request runs only mocked read-only ownership tests. Only an exact, current, checked-out Infra `main` SHA may build and publish. Staging publication runs serially with no other staging owner.
- Run `python3 scripts/portal_pages.py preflight` to inventory (GET-only) with appropriate credentials; `verify --sha <40-hex>` performs public no-bypass TLS and asset validation.
- Rollback before root promotion: keep production DNS unchanged; later redeploy a previous known-good SHA in the same dedicated staging Pages project after approval. Never overwrite a foreign DNS entry.
- **Production/root** `shadowops.dpdns.org` is **separate and intentionally not implemented here**. First verify staging and inventory the apex record. Promotion must be reviewed separately and preserve rollback. See #153 for eventual final art/hardware-GPU acceptance.

This file describes release infrastructure, not confirmation of a successful live DNS record or staging deployment.
