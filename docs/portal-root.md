# ShadowOps Universe — root-domain release safety

Staging is published first at **https://staging.shadowops.dpdns.org**. The owner of `shadowops.dpdns.org` must be established **before** any root Pages domain or CNAME mutation.

The read-only workflow `portal-root-inventory.yml` uses trusted Infra staging secrets on **main only**. It prints three non-sensitive classifications for the apex record and the *dedicated future* `shadowops-universe-production` Pages project:
- `absent`: safe to consider creating the missing resource.
- `owned`: exact project/target, safe to reconcile idempotently.
- `foreign` or `ambiguous`: **do not overwrite or delete**. Examine whether a preexisting application/owner would be displaced.

The workflow makes **zero POST/PATCH/PUT/DELETE calls**. It must never inventory/change Chess Studio, Chronicles, Star Adventures or the existing Cloudflare Tunnel as a side effect. A separate production PR must consume only an **immutable verified staging build artifact**, not rebuild an unverified later version or blindly point a DNS record.

Only a completed verified artifact + public HTTPS + source SHA can be called a deployed release. This document does not authorize automated deletion of any root record.
