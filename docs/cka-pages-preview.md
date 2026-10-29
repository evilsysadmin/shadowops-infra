# CKA // LAB · Cloudflare Pages public preview

Owner of infrastructure: evilsysadmin/shadowops-infra.
Application source and tests: evilsysadmin/cka-exam-simulator.

## Immutable ownership boundary

- Hostname: https://cka.shadowops.dpdns.org
- DNS zone: shadowops.dpdns.org
- Exclusive Pages project: cka-simulator; target: cka-simulator.pages.dev
- Artifact: CKA frontend dist-public (never the development build)
- Runtime: STATIC READ-ONLY DEMO. No Kubernetes runner, kubeconfig, credentials, API endpoint or public shell.
- Release identity: /release.json with mode static-readonly-preview and source SHA.

The owner workflow is the sole publisher. PR checks never use Cloudflare credentials or mutate DNS.
On Infra main push affecting this publisher, it builds CKA main at an exact SHA, validates the safe output, refuses superseded source or owner main, and performs strict read-only Cloudflare preflight before creating any project or domain. Existing DNS not pointing to cka-simulator.pages.dev is rejected, never overwritten. Chronicles and Chess Studio remain untouched.

It uses protected Infra staging environment/repository secrets CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID. If missing or insufficient, the publication fails closed. Successful PR/CI is not proof of a deployed site. Require a successful publish job, marker CKA_PUBLIC_PREVIEW_LIVE_SHA_OK and artifact cka-pages-preview-SHA.

For deliberate retry, manually dispatch CKA Simulator public static Pages preview from shadowops-infra main. No other resource owner should publish the same hostname.

Before enabling real CKA exam sessions on the Internet: require auth, per-user VM isolation, TTL, quotas, limited kubeconfig, rate limiting, audited and isolated terminal transport, and cross-tenant security tests. A kind smoke in CI is not sufficient.
