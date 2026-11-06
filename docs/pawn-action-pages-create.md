# Pawn Action · empty Pages project reservation

Only reserve the name "pawn-action-staging" as a Cloudflare Pages
Direct Upload project. This is not a deployment, DNS record, authenticated
game or private staging receipt.

Cloudflare Pages documents a direct-upload project creation using a
single POST to /accounts/{account_id}/pages/projects with the required
"name" and "production_branch" fields:
https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/create/

Offline plan:
    python3 scripts/pawn_action_pages_create.py plan

The "Pawn Action · empty Pages project create-once" workflow on Infra
main can be explicitly dispatched with operation=reserve and
confirm_project=pawn-action-staging. The protected staging environment must
have independent CLOUDFLARE_API_TOKEN (read-only inventory),
CLOUDFLARE_ACCOUNT_ID, and PAWN_ACTION_PAGES_PROVISION_TOKEN (Pages Write).
The two token values MUST be distinct. PR/push jobs run offline tests only
and never receive Cloudflare credentials.

Reservation checks the existing zone, exact Pages name, source type,
canonical subdomain and absence of custom staging DNS/domain. It also
checks the project `latest_deployment`/`canonical_deployment` metadata
and reads `GET /accounts/{account_id}/pages/projects/pawn-action-staging/deployments?per_page=1&page=1`
**without a production-only filter**: even one preview deployment means the
project is not empty. Missing permissions, malformed inventory or absent
deployment metadata fail closed, including for an already-existing project.
It performs at most one POST and rechecks ownership. A conflict, transport timeout,
foreign resource, wrong account, unexpected deployment, or public custom
domain is NOT retried or modified automatically. Re-inventory manually
before another attempt; there is no rollback DELETE.

A reserved Pages namespace may still have a public `pages.dev` alias.
The strict inventory makes sure the reservation itself contains zero
deployments, but is only a point-in-time check, not a distributed lock.
It does not prove any holding Worker is deployed or that an existing project
is safe to serve game files in the future. Do not publish any app until the private R2 bucket,
ShadowOps ID consumer, locked-edge gate and explicit visual acceptance are
independently established. Pawn Action source PR #1 remains Draft and
Chess Studio's legacy pointer/production remain unchanged.
