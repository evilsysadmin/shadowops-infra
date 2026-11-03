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
2. Implement a separate exact-SHA release admission from a green Pawn Action
   main build. Require the validated Godot Web artifact, its content hashes,
   browser input checks and the visual acceptance evidence.
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
