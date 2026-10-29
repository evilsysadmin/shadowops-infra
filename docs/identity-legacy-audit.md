# ShadowOps Identity P0 · Legacy public JWKS preflight

The current identity provider is still Chess Studio. Before attempting any Strangler cutover, verify that legacy **staging** and **production** publish different Ed25519 signing keys. This is only one identity-boundary check, not proof of independent accounts, correct token validation, runtime auth security, or readiness for extraction.

Run the **manual** workflow `ShadowOps Identity · legacy JWKS separation audit` on `shadowops-infra/main`. No secrets, Cloudflare write permissions, SSH, private account data, or deployment actions. An operator may also run `python3 scripts/identity_legacy_audit.py`. CI only exercises offline mocks.

Audited legacy origins: `https://api-staging.chess-studio.shadowops.dpdns.org` and `https://api.chess-studio.shadowops.dpdns.org`. The job retrieves only each `/api/identity/jwks`, checks the published key type/algorithm/usage and rejects any overlapping public signing key fingerprint. Redirects to a different host, missing endpoints, invalid JSON, malformed JWKS and unexpected network errors fail closed. Logs reveal only number of keys per environment, never tokens or private secrets.

**Passing this audit is NOT authorization to migrate users or enable CKA login.** Next phase remains inventory of account persistence, password/session compatibility, issuer migration and rollback in staging. Follow [roadmap](ROADMAP.md) / [#287](https://github.com/evilsysadmin/shadowops-infra/issues/287).
