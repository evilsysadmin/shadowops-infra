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

## Gates de aceptación / amenazas principales

- Cross-env token (incluyendo mismos nombres de usuario), wrong aud, tampered alg/kid, key rotation invalidada, expired/not-yet-valid, replay / session fixation -> rechazo.
- CORS con credenciales sólo para orígenes fijados y CSRF mitigado en toda ruta de cookie que muta sesión; no depender únicamente de SameSite; cookies host-only + Secure + HttpOnly. Audit logs sin credenciales.
- Escalada lateral de privilegios: ID global no equivale a rol admin. Roles por producto, privilegios de servicio revisables y tenant isolation estricta.
- Resiliencia: nuevo IdP es punto único de login; diseñar health, backups, restore, rotación de claves, métricas sin PII y recuperación de incidentes.
- Relacionar KMS/Vault y rotaciones con `kid` y periodo de verificación de tokens anteriores (ej. ≤ duración máxima + tolerancia de reloj), sin compartir JWT_SECRET de Chess tras la extracción.
- Un PR de Infra no muta producción. No retirar/revocar emisor legacy hasta probar rollback.

**Source of truth machine-readable:** `config/identity/platform-contract.json`. Direcciones objetivo, no endpoints desplegados ni DNS confirmado.
