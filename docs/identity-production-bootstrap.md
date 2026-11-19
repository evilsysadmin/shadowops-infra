# ShadowOps Identity · separate production TLS bootstrap (not activated)

This is a **deliberately unready** first production-only runtime milestone.
It is **not** a user-facing identity provider and cannot authenticate anyone.

## Security and architecture

- The executable \`services/identity/cmd/service-production\` is distinct from
  \`cmd/service-staging\`. It does **not** reuse the staging Mongo database,
  cookie, issuer, signing key, user accounts or service proof.
- Configuration is read only from an explicitly named, absolute private
  \`IDENTITY_PRODUCTION_CONFIG_FILE\` (regular file, not symlink, no group or
  world permissions, bounded JSON, no unknown keys/trailing documents).
- \`environment\` must be \`production\`, the issuer derived by
  \`core.New("production", seed)\` is \`https://id.shadowops.dpdns.org\`, and
  the certificate is valid for exactly \`id.shadowops.dpdns.org\`.
- Mongo connection data must name \`shadowops_identity_production\`, have
  credentials, TLS enabled, an explicit CA and no insecure TLS options.
  This is an **offline contract check**; no Mongo connection or RBAC
  verification occurs yet.
- Only the production \`bridgesquad\` audience is admitted in this initial
  bundle. It uses its own canonical \`soc1_\` consumer proof. Signing key,
  TLS private key and consumer credential must not be interchangeable.
  Distinct custody from staging is still an operator provisioning requirement.
- **No credential/session/refresh/revocation/JWKS issuance is available.**
  Even with a valid bundle, \`/readyz\`, \`/api/identity/jwks\`,
  \`/login?app=bridgesquad\` and all Identity API routes return HTTP 503.
  Only \`GET /livez\` over the exact HTTPS production host returns 200;
  its body explicitly states that auth is disabled.
- \`cmd/service-production\` has no default start behavior. \`preflight\`
  validates the bundle; \`serve-unready\` is an **explicit opt-in** to a
  TLS listener at :9443, still entirely unready for authentication.
- There is **no production container deployment, Cloudflare/DNS write,
  OCI mutation or secret provisioning** in this change. The test workflow
  runs offline Go/Race/Vet and builds amd64/arm64 executables without publishing.

Do **not** point \`id.shadowops.dpdns.org\` or
\`bridgesquad.shadowops.dpdns.org\` at this bootstrap. It cannot sign
tokens for users, confirm account state or perform authoritative freshness
checks, and the existing game must continue to deny guests.

## Next increments required before any activation

Add an independent production Mongo issuer and atomic account/session
transactions, production-native user account handling, per-consumer signed
EdDSA tokens, authoritative freshness/revocation and isolated service proof.
Review least-privilege production Mongo roles, implement real browser/TLS
login with CSRF controls, then test an authenticated browser login and
immediate revocation end-to-end before provisioning the protected Cloudflare
binding or changing DNS.

Tracked in [Identity P0 #287](https://github.com/evilsysadmin/shadowops-infra/issues/287)
and [Bridge Squad activation #611](https://github.com/evilsysadmin/shadowops-infra/issues/611).

## Sesiones Mongo de producción · almacén independiente

El paquete `services/identity/production/session_store.go` implementa `session.Store` para el nombre **exacto** de base de datos `shadowops_identity_production`, con operaciones Mongo de escritura `majority`, lectura del primario e índices únicos por `environment,digest`, TTL y revocación por `environment,subject`.

`NewSessionStore(ctx, db)` crea/verifica los índices al aprovisionar; `OpenExistingSessionStore(db)` solo abre una colección ya provisionada y **no demuestra** por sí mismo que los índices o los permisos RBAC sean correctos. El operador deberá auditar la identidad del principal Mongo, su TLS/CA, los índices y permisos exactos antes de habilitar el futuro emisor. Este código no abre conexiones ni produce secretos por sí mismo.

Todas las escrituras/lecturas/revocaciones admiten únicamente `environment=production`, UUIDv4 y **`session_version > 0`**. Las sesiones antiguas sin versión y los documentos corruptos no se consideran válidos. La rotación usa un `UpdateOne` condicionado a digest, sujeto, versión y expiración original, sin insertar registros ni ampliar su vencimiento; la eliminación por sujeto invalida todas sus sesiones. Estos contratos tienen pruebas concurrentes y negativas contra Mongo efímero en CI (nunca contra la base de datos real).

**Importante:** el almacén aún NO está conectado al bootstrap HTTP, a cuentas autenticadas ni al firmante de tokens. No se crean sesiones reales ni se activan los endpoints del producto por este cambio. El siguiente paso es la unión transaccional de autenticación de cuenta + versión de sesión + emisión y revocación, sin copiar los handles ni las colecciones de staging.

## Autoridad nativa de cuentas de producción (todavía sin API pública)

`services/identity/production/accounts.go` introduce `NewAccountAuthority(ctx, client)` para la base **exacta** `shadowops_identity_production` y la colección exclusiva `native_accounts`. La autoridad crea índices de alias únicos por entorno/origen y usa el almacén de sesiones de producción. Su cliente Mongo **debe** haberse creado previamente con identidad TLS, CA, usuario RBAC y credenciales de producción validados por el operador; una referencia `*mongo.Client` no puede demostrar por sí sola su procedencia.

`Register` es, por ahora, **una primitiva interna** de registro nativo nuevo que exige alias ASCII normalizado y contraseña de al menos 15 caracteres UTF-8, almacenada con hash Argon2id. No importa alias heredados, cuentas de staging, roles administrativos ni datos de los juegos. Las operaciones de recuperación y mantenimiento de credenciales todavía no tienen API de producto y deben incorporarse antes del registro público.

`Issue` verifica una cuenta nativa activa y une la escritura de la cuenta (`login_fence`) con la inserción de la nueva sesión versionada dentro de **una misma transacción Mongo snapshot/majority**. La suspensión `SuspendAndRevoke` escribe en el mismo documento, marca la cuenta suspendida, incrementa `session_version` y elimina sus sesiones en la misma transacción. El conflicto impide que un login simultáneo deje una sesión válida después de la suspensión. Los handles opacos nunca se guardan en texto plano; se almacena su SHA-256 separado mediante el prefijo criptográfico `shadowops-session-v1:production:`.

`Validate` exige la coincidencia de sesión persistida, vencimiento, versión y cuenta activa mediante `session.NewVersionedValidator`. Es solo una **observación en un instante**, no una concesión permanente para ejecutar operaciones de un juego: la autorización final debe comprobar la vigencia de cuenta/sesión/JTI de token contra Mongo en cada operación protegida.

La CI `identity-replica.yml` añade pruebas con MongoDB replica set local y desechable: contraseña incorrecta, alias legado, cuenta duplicada, transacción de login, suspensión, eliminación de sesiones y cuatro emisiones concurrentes compitiendo con una suspensión. **No se ha desplegado ni conectado este backend a `cmd/service-production` ni a HTTP**, el IdP todavía no emite JWT productivos y Bridge Squad continúa en su pantalla de cuarentena 401.

## JWT EdDSA de producción y frescura JTI (backend interno)

`services/identity/production/app_tokens.go` incorpora `NewProductionAppTokens` con **emisor fijo** `https://id.shadowops.dpdns.org` y **audiencia fija** `bridgesquad`. La semilla Ed25519 debe venir del futuro aprovisionamiento independiente de Vault; nunca de staging ni de una variable del frontend. `JWKS()` publica solo la clave pública; el token `Issue(ctx, handle)` exige un handle opaco de una sesión versionada de producción y emite JWT EdDSA con `iss/aud/sub/iat/nbf/exp/sv/jti` y caducidad máxima de 120 segundos. No se aceptan audiencia, sujeto o claims proporcionados por el navegador.

La creación verifica la sesión persistida y actualiza `login_fence` de la cuenta activa en **la misma transacción Mongo snapshot/majority** en la que escribe el vínculo entre JTI y digest de sesión en `production_application_tokens`. Firma el JWT **solo después del commit**. La colección mantiene un índice TTL y no almacena JWT, JTIs legibles, handles de navegador ni claves privadas: el identificador persistido es el SHA-256 con separación de dominio `shadowops-app-token-v1:production:bridgesquad:`.

`VerifySignature()` comprueba la firma y los claims, **pero por sí solo no autoriza operaciones**. `Check()` exige además comprobar el JTI, la sesión y la cuenta activa, ligadas a la versión vigente. `CheckBound()` es una función interna de *freshness*: hace escrituras condicionales en los tres documentos dentro de una transacción para impedir que lecturas de snapshots anteriores ignoren una suspensión, una eliminación de sesión o una desactivación de token. Sus evidencias (`issuer`, `audience`, `subject`, `session_version`, `token_jti`, `checked_at`, tres booleanos de actividad) coinciden con el contrato del Worker de Bridge Squad. La evidencia describe **un instante**, no una sesión irrevocable; el consumidor debe repetir la comprobación en cada operación protegida.

La CI `identity-replica.yml` cubre firma JWKS, pruebas contra Mongo replica set local, revocación y logout, audiencia/issuer erróneos, JWT alterados, JTIs no registrados y concurrencia entre comprobación y suspensión. `CheckBound()` **no tiene ruta HTTP**: una ruta futura deberá verificar con secreto independiente en Vault que el solicitante es el Worker de Bridge Squad, fijar audiencia y host sin confiar en campos del navegador y exigir sus propios controles de replay/abuso.

**Aún no hay IdP de producción desplegado, endpoint de login, endpoint público de tokens o de frescura ni binding de servicio activo.** `cmd/service-production` continúa devolviendo HTTP 503 en rutas de autenticación. No se ha modificado Cloudflare ni levantado la cuarentena de `bridgesquad.shadowops.dpdns.org`. Seguimiento #287 y #611.

## Transporte HTTPS interno de frescura para Bridge Squad (sin despliegue)

`services/identity/production/http_freshness.go` incorpora un handler opt-in `NewProductionFreshnessHandler(authority, secret)` que **no está conectado** a `cmd/service-production`. El servicio solo admite el host TLS exacto `id.shadowops.dpdns.org`: ignora cabeceras `X-Forwarded-*` como prueba de origen, exige dirección remota IP válida, y rechaza `Origin`, `Cookie`, `Referer` y `Sec-Fetch-Site` en la ruta de servicio.

El único endpoint autenticado del handler es `POST /api/identity/freshness`, con `Authorization: Bearer soc1_...` independiente de las claves JWT y secreto retenido únicamente como SHA-256 separado por entorno y audiencia. Rechaza credenciales ambiguas, múltiples cabeceras, métodos distintos, JSON comprimido, campos desconocidos, cargas mayores de 4096 bytes, `subject` no UUIDv4, versiones no positivas y JTIs no canónicos. El cuerpo solo contiene `subject`, `session_version` y `token_jti`: nunca se permite seleccionar un `audience` o `issuer` desde la petición. No se registran contraseñas, tokens ni secretos. La ruta llama a `CheckBound`, que comprueba en Mongo el JTI vigente, la sesión y la cuenta activa en una transacción de frescura. Los errores de autenticación son 401 y los fallos de almacenamiento, 503; no se revelan detalles de Mongo.

El handler puede servir `GET /api/identity/jwks` sin cookies ni autorización (clave pública únicamente). Sin embargo, `/readyz`, `/login` y las demás rutas de sesión/token **continúan devolviendo 503**: falta construir el login de navegador y conectar un runtime completo con infraestructura real. La prueba de integración emplea MongoDB replica set **efímero**, verifica acceso con secreto correcto, denegación con secreto equivocado, sujeto/versión/JTI cruzados, suspensión, logout y desactivación de token.

**Aviso de despliegue:** no vincular esta capa a un listener público hasta provisionar un secreto `bridgesquad` nuevo desde Vault, la base Mongo y el TLS productivos, el emisor/sesiones HTTPS y pruebas del flujo de navegador. El Worker existente de Bridge Squad continúa en cuarentena 401 y el dominio no se reconfigura con esta PR. Seguimientos #287 y #611.
