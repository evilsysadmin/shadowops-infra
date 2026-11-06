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

## Inspección real, solo lectura (sin reservar ni desplegar)

Antes de usar el token de escritura, ejecutar manualmente en Infra `main`
**Pawn Action · empty Pages project create-once** con `operation=inspect`.
El job requiere el entorno protegido `staging` y únicamente
`CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` con permisos de lectura
de Pages, zonas y DNS. **No recibe** `PAWN_ACTION_PAGES_PROVISION_TOKEN`
ni `PAWN_ACTION_PAGES_DEPLOY_TOKEN`. En PR/push solo se ejecutan tests offline.

El recibo `PAWN_ACTION_PAGES_READINESS` informa:

- `not_reserved`: el proyecto Pages y DNS no existen; el siguiente paso,
  si se autoriza, es la reserva manual `operation=reserve`.
- `reserved_empty`: Pages pertenece al proyecto correcto, sin dominio ni
  DNS, sin deployments preview/production y con metadatos de último
  deployment nulos; siguiente paso: `pawn-action-locked-pages-deploy.yml`.
- `locked_alias_verified`: exactamente un primer deployment `production`,
  IDs latest/canonical coincidentes y respuestas públicas GET/HEAD sin
  archivos servidos en el alias `.pages.dev`; siguiente gate: dominio
  canónico separado y verificación del shell bloqueado.

Preview-only, múltiples deployments, DNS/dominio ya adjuntado, proyecto
ajeno, metadatos inconsistentes, fallo de lectura o un alias que sirva
contenido fallan **cerrado**. No intentamos reparar, sobrescribir,
borrar o repetir operaciones de Cloudflare. La inspección produce una
fotografía puntual, no garantiza exclusión mutua frente a un tercero.
Un recibo verde no acredita juego publicado, autenticación o aceptación
visual de la PR principal de Pawn Action.
