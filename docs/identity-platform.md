# ShadowOps Identity · Architectural Decision Record P0

**Estado: PROPUESTA CONTRACTUAL, sin cambios operativos.** Seguimiento: [#287](https://github.com/evilsysadmin/shadowops-infra/issues/287).

## Contexto confirmado en código

- `chess-studio/backend-go/internal/gamesapi/sso.go` funciona como IdP actual. Emite tokens **EdDSA/Ed25519** para audiencia Chronicles, publica JWKS y utiliza cookie SSO host-only. El login heredado de Chess sigue presente.
- `chronicles-of-matthias/frontend/src/shadowopsIdentity.js` usa `/api/identity/session` y `/api/identity/token`; `api/internal/ssoauth/ssoauth.go` valida JWKS con issuer y audience.
- El contrato actual fija emisores `api-staging.chess-studio...` y `api.chess-studio...`, y sesión JWT propio de Chess de 30 días. Su función de firma está acoplada actualmente a `JWT_SECRET` de Chess.
- **No es todavía un servicio de identidad autónomo ni un OIDC provider estándar.** Mantenerlo operativo durante la transición y no proclamar un despliegue nuevo hasta tener evidencia de endpoint.

## Decisión

Separar **identidad** de **autorización por aplicación** y de **operación de infraestructura**:

1. Código y pruebas del servicio Identity en repo independiente propuesto; `shadowops-infra` es propietario de DNS, OCI, Cloudflare, Vault, configuraciones y release trains, **no** de las contraseñas en repositorio.
2. Dos instancias **aisladas**: Identity Staging y Identity Production. Sin cuentas, claves, DB, cookies, credenciales de Mongo ni backups compartidos. El mismo texto de username entre entornos nunca constituye una cuenta común.
3. Todos los consumidores del mismo entorno reutilizan la misma cuenta de Identity, pero cada servicio conserva sus partidas, progreso, historial, autorización y concesiones administrativas. El identificador inmutable `sub` es estable en un entorno; las migraciones de username legacy usan mapeo explícito con prueba anti-colisión.
4. `iss` y claves publicadas via JWKS fijos por entorno y `aud` explícita por producto. Validación fail-closed del par issuer/audience, firma, claves, tiempos y session state.
5. No acoplar los privilegios de clúster de CKA con la autenticación del usuario: aislamiento/TTL/cuotas/roles de acceso se imponen en su propia API/runner.

## Patrón de migración

- **Strangler Fig**: extraer responsabilidades del IdP Chess por rutas/consumidores; no reemplazar en un big bang.
- **Branch by Abstraction**: contrato de verificación por aplicación detrás del cual puede estar Chess IdP o ShadowOps Identity. Mantener tests de equivalencia y compatibilidad.
- **Expand–Contract**: ventana temporal acotada de confianza en emisor legacy **del mismo entorno** y emisor nuevo; nunca confiar en staging y prod simultáneamente. Retirar la compatibilidad al final del cutover.
- **Parallel run sin dobles escrituras**: pruebas de identidad y validación de firma contra datos de prueba y usuarios migrados con autorización, sin replicar contraseñas indiscriminadamente ni emitir sesiones productivas desde los dos IdP a la vez.
- **Canary/reversible rollout**: staging primero, luego producción mediante aprobación, siempre con métricas, recibo SHA, pruebas de login/logout/refresh reales y rollback ensayado.

## Fases de cambio y rollback

1. **P0.0** Contratos y CI sin secretos ni despliegues (este PR). Evidencia: validadores de forma y de aislamiento.
2. **P0.1** Examinar dependencia de Mongo/secretos de Chess y seleccionar mecanismo de extracción que preserve hashes Argon2id/bcrypt sin introducir copia de contraseñas en repositorios. Backups probados; plan de link de cuentas y UUID; límites de sesión.
3. **P0.2** Servicio Identity staging aislado, rotación de clave sin romper consumers, health/JWKS/login/logout/refresh y rate limit. Orígenes autenticados allowlist; cookies host-only. Evaluar cookies y flujos OAuth/OIDC antes de usarlo desde un producto público.
4. **P0.3** Clientes staging con opt-in, pruebas contra emisor nuevo y legado del **mismo entorno**; reversiones por consumidor. No mover datos de juegos.
5. **P0.4** Producción con identidad, DB, keysets, secret stores y restore separados; despliegue manual por SHA validado y pruebas cross-environment negativas. Mantener Chess legacy activo hasta completar migración.
6. **P0.5** Consumidores production uno a uno. CKA sólo después de esta plataforma y de su propio control de acceso a laboratorios.

## P0.1 · Suite criptográfica de referencia antes de la extracción

La suite `scripts/identity-token-contract.mjs` + `tests/identity-token-contract.test.mjs` valida **firmas Ed25519 reales en memoria** (Node `crypto`) contra el contrato `config/identity/platform-contract.json`. Falla para `iss` de otro entorno, `aud` de otra app, claves de otro entorno, firmas inválidas, tiempos caducados/futuros y `kid` desconocido; admite una rotación temporal con dos claves públicas del mismo emisor.

**Es un harness contractual offline, NO un middleware productivo**: no canjea cookies, no crea cuentas, no acepta un IdP remoto, no equivale a completar OIDC y no concede permisos. En particular `assertConsumerActivated` deniega todo consumidor aún no acreditado, incluida la preview pública CKA. Los consumidores finales deberán aplicar estos mismos casos negativos en sus propias implementaciones y pasar pruebas de sesión reales antes de cambiar un solo login.

No existe modo de aceptar staging y production como un único `iss`. Cualquier compatibilidad temporal con el emisor legacy se diseña y valida explícitamente **sólo dentro del mismo entorno**; nunca se habilita automáticamente.

## P0.1 · Preflight de cuentas legacy con UUID estable

**Hallazgo verificado en el repositorio Chess Studio:** `backend-python/users_store.py` y `backend-go/internal/accountstore/store.go` usan Mongo `users._id = username`; las cuentas tienen `password_hash` y `session_version`. Por tanto, no podemos reemplazar `sub=username` por UUID sin una tabla de alias/migración que preserve las partidas y los permisos de cada juego.

`scripts/identity_link_preflight.py` valida **offline** planes explícitos de vinculación de cuentas por entorno y producto. Sólo acepta `source`, `username`, `subject` (UUIDv4) y `link_review_ref` (ticket de revisión) por entrada; bloquea colisiones casefold/NFKC, duplicaciones internas, identidad UUID compartida entre staging y production, y fusionar cuentas de Chess y Chronicles sin una revisión explícita común. **Un mismo username en dos juegos NO vincula automáticamente las cuentas.** Cualquier ticket de revisión debe verificarse humanamente; su presencia no acredita propiedad.

No carga ni transforma hashes, correos, sesiones, secretos ni privilegios. No genera UUIDs y **no realiza escrituras** en Mongo ni en sistemas SSO. La herramienta imprime exclusivamente cantidades agregadas. Si se usa con cuentas reales, los planes privados deben residir fuera de GitHub, CI, artefactos y logs, y borrarse de forma segura tras la ventana aprobada. En CI sólo se ejecutan fixtures sintéticos. La migración de cuentas y el backup/restore siguen pendientes.

## Gates de aceptación / amenazas principales

- Cross-env token (incluyendo mismos nombres de usuario), wrong aud, tampered alg/kid, key rotation invalidada, expired/not-yet-valid, replay / session fixation -> rechazo.
- CORS con credenciales sólo para orígenes fijados y CSRF mitigado en toda ruta de cookie que muta sesión; no depender únicamente de SameSite; cookies host-only + Secure + HttpOnly. Audit logs sin credenciales.
- Escalada lateral de privilegios: ID global no equivale a rol admin. Roles por producto, privilegios de servicio revisables y tenant isolation estricta.
- Resiliencia: nuevo IdP es punto único de login; diseñar health, backups, restore, rotación de claves, métricas sin PII y recuperación de incidentes.
- Relacionar KMS/Vault y rotaciones con `kid` y periodo de verificación de tokens anteriores (ej. ≤ duración máxima + tolerancia de reloj), sin compartir JWT_SECRET de Chess tras la extracción.
- Un PR de Infra no muta producción. No retirar/revocar emisor legacy hasta probar rollback.

**Source of truth machine-readable:** `config/identity/platform-contract.json`. Direcciones objetivo, no endpoints desplegados ni DNS confirmado.

## ShadowOps Identity account roles (staging, additive contract)

The central account has exactly one platform role: `user` (default) or
`admin`. Newly registered accounts are **always** persisted with
`role=user`; older records without a role are interpreted as `user`.
Invalid or noncanonical role strings fail closed. No user-supplied registration
field, display alias, same-name legacy login, frontend flag or unsigned token
may elevate the role.

`admin` represents **Identity platform administration**, not a wildcard
that grants game, Kubernetes, cloud, tenant or billing privileges. Each
product remains responsible for its own scoped grants after authenticating
the immutable `(iss, sub, aud)`. A central `admin` grant must use an
audited, operator-approved, immutable subject and require a separate
privileged workflow; this first contract **does not expose** a self-service
grant endpoint, mutate existing accounts, add JWT role claims or grant an
operator account implicitly.

For the missing Chronicles staging panel, the already implemented product
allowlist `shadowops:staging:<UUIDv4>` remains the controlled path to
restore access to a verified owner. This central roles vocabulary is not
that grant and does not close Chronicles issue #1029. Production remains
unmodified.

### Explicit approval for changing a platform role (staging, offline contract)

`services/identity/roles/approval.go` now defines a **pure**, separately
domain-bound authorization request for one `user ↔ admin` transition.
It requires the immutable staging UUIDv4, expected current role, positive
session-version fence, signer policy generation, review issue, private evidence
SHA-256 digest, unique nonce, five-minute validity and **two distinct,
independently provisioned Ed25519 signers** (operator + security).
All signatures bind the entire request; production, usernames, wildcards,
changed fields, expired or unsigned requests are denied.

**This is not yet a role-grant mechanism.** The separate operator executor
must verify both configured keys against an *active, versioned server-side
policy* and independently reviewed account ownership, then atomically
compare-and-swap the live active account, bump its session version, revoke
existing sessions/tokens, consume a globally unique nonce and append a
permanent audit event in the same majority Mongo transaction. Bootstrap
and RBAC permissions must restrict the executor independently from the
public Identity service. Do not enable any browser-side role mutation or
copy real subjects/approval material into PRs or logs.

Until that executor and its operational gates are verified and deployed,
**no real account can become `admin` through this contract**. Likewise,
a platform `admin` does not automatically become a Chronicles game admin;
the product-scoped staging grant and incident #1029 are separate.

### Atomic operator-only role executor (staging)

`services/identity/roles/executor.go` adds an **unwired, offline**
`StagingRoleExecutor` for **one** signed `user ↔ admin` change. It requires
two independently approved Ed25519 signatures, an active and versioned
`admin_signer_policy` record with ID `staging:set-role`, exact pinned
public-key hashes and the account's current session-version/role. Every
attempt rechecks signatures and policy in a snapshot/majority transaction.
The policy itself receives a write fence to conflict with concurrent
retirement/rotation. Only a trusted operator can invoke this primitive;
the browser login, session token and public Identity HTTP server have no
role-change route or access to operator signing keys.

A successful transaction changes the exact staging account's role, bumps
its `session_version`, deletes browser sessions, deactivates bound
`staging_cka_tokens` and appends one permanent audit entry with
`environment`, `action`, `nonce`, role transition, review reference,
evidence digest, approved signer key hashes and timestamps. There is no
automatic transfer of game privileges. Unknown roles, invalid signatures,
stale session versions, retired policy, replayed nonce and unauthorized
subjects fail closed and roll back **all** writes.

**Operator bootstrap still required; no grants are active on merge.**
An independent database schema maintainer must create a unique,
non-sparse, non-partial, non-TTL index named
`staging_role_nonce_unique` on
`shadowops_identity_staging.admin_role_change_journal` keys
`{environment:1,action:1,nonce:1}`. The executor only **checks** this
index; it never creates or repairs it. A separately approved signer
policy record `staging:set-role` must also be established with pinned
operator/security keys and a restricted validity window. An offline
operator account needs narrowly scoped read/write to those exact
collections; **never** reuse the live Identity runtime's Mongo credentials
or add the new journal/policy privileges to its account. Before any real
grant, establish the protected operation, independently review the
target's immutable `sub`, test rollback and revocation in staging,
and validate least privilege and audit retention.

## Acceptance: one ShadowOps account, no repeated product registration

The shared Identity goal means one central registration/login/recovery flow per
environment. After signing in, the same person must enter Chess Studio,
Chronicles and CKA without another registration or another product password.
Each product may initialize its own idempotent profile keyed by the verified
`(issuer, subject)`, but that is local application data, not a second identity
account. Shared login never implies shared admin or Kubernetes permissions.

End-to-end acceptance must demonstrate central registration (or explicitly
verified legacy linking), one login reused across the three products, refresh,
central logout/revocation rejected by each consumer, recovery, and negative
cross-environment/cross-audience cases. Existing usernames must not silently
merge identities or transfer saved games. Staging and production remain isolated.
The legacy Chess/Chronicles flow remains available until the replacement has
passed those journeys and rollback. Cryptographic PoCs, internal libraries and
green unit tests alone do not establish that this user-visible goal is delivered.

### Shared-session milestone (internal staging library)

The issuance/freshness library now recognizes the three configured application
audiences over one central session, with a 3×3 wrong-audience rejection matrix.
Central-session logout and rotation invalidate that session's tokens across the
three products, while other browser sessions remain isolated. Existing CKA
interfaces and registered-record layout stay compatible. This does not complete
the user-visible acceptance above: browser registration/login, service transport
and consumer wiring are still pending; the legacy logins remain untouched.

### Browser transport milestone (opt-in, unpublished staging)

`services/identity/websession` now exposes HTTPS login, per-origin token
exchange, refresh and central logout over the real Mongo issuer. Synthetic
TLS + replica-set tests exercise one cookie across the three audiences and
revocation/rotation. The new host's staging cookie uses the `__Host-` prefix,
Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, superseding its earlier
design-only name/path. The legacy Chess IdP cookie and all product logins stay
unchanged. See [the transport contract](../services/identity/websession/README.md).

This is not central account enrollment or an application login cutover. The
transport currently takes an active central UUID and password; it never activates
pending legacy accounts or resolves their usernames. Registration/login UI,
verified data linking, trusted freshness transport and consumer adapters remain
required. The bootstrap still returns `/readyz=503`; no endpoint is published.

### Central account entry (local browser preview)

The opt-in `NewStagingBrowserHandler` adds new native central accounts,
username/password login, one-time backup-code recovery and an embedded Spanish
login/signup/recovery page. It returns only to pinned product origins, without
tokens in URLs. New registration never claims or activates legacy names/data.
Recovery rotates its proof and revokes all browser/application sessions in one
Mongo transaction. Actual Chromium desktop/mobile tests cover this central UI
and cross-origin cookie reuse by three **synthetic** product pages. This is not
an actual Chronicles login cutover: backend freshness transport, consumer profile
binding and staging runtime/deployment remain outstanding.

### Configured staging runtime (source/image handoff)

`cmd/service-staging` now connects the browser and freshness flows to a private
staging bundle, direct TLS and a narrowly authorized, authenticated Mongo replica
set. Startup verifies actual effective privileges and rejects admin, overbroad
or incomplete roles. CI exercises the real TLS/SCRAM startup/account journey and
builds/scans both architectures before protected-main image publication. See
[the runtime contract](../services/identity/runtime/README.md).

Chronicles consumer source is merged in
[Chronicles #944](https://github.com/evilsysadmin/chronicles-of-matthias/pull/944),
with backend/frontend opt-in disabled by default. This is not an active DNS,
provisioned database, deployed service or completed public browser journey.
