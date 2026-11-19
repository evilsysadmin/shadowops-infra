# Matthias Bridge Squad — production ShadowOps ID admission

**Requested hostname:** `https://bridgesquad.shadowops.dpdns.org/`

**Status: source-only gate / DEFAULT OFF. Not a live deployment.** The independent ShadowOps Identity HTTP application token issuer in Infra is currently staging-only. Its `StagingAppSigner` refuses production configuration and its closed audience registry does not yet contain `bridgesquad`. The `id.shadowops.dpdns.org` hostname is a production *contract*, not evidence of a running independent production service. Do not reuse `id-staging` accounts, keys, sessions, or service proofs on this production hostname.

## Strict edge contract

- Pages production project reserved name: `bridgesquad-production`, owned by ShadowOps Infra, not the game repository.
- Hostname: exactly `bridgesquad.shadowops.dpdns.org`. Unknown hosts, Pages `*.pages.dev` and preview deployment aliases get 404 without reaching assets.
- Expected JWT: Ed25519, `iss=https://id.shadowops.dpdns.org`, `aud=bridgesquad`, two-minute maximum, UUIDv4 `sub`, correct `sv`, `jti`, expiry, nbf, JWKS signing key, and live freshness RPC per request.
- Binding: `SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL`, a consumer-specific `soc1_` secret retrieved and installed by an audited Infra operator only. It must never be in the game repo, GitHub artifacts, source PRs, or browser storage.
- A verified session receives a Secure/HttpOnly, host-only, SameSite=Lax `__Host-bridgesquad` cookie. The unauthenticated root gets a separate 401 login shell, **not game assets**. Other resources and protected JS get 401/503.
- Wrong issuer/audience, revocation, missing proof, Identity unavailable or invalid JWT: fail closed. Tests use synthetic in-memory keys and fake freshness, **not a real Identity sign-in**.

## Activation checklist (not automated in this PR)

1. Obtain a separately reviewed, operational **production** ShadowOps Identity deployment with production Mongo, signing keys, session/revocation, backups and independent credentials. Confirm `/login?app=bridgesquad`, `/api/identity/token`, JWKS and freshness transport are live and the new exact-origin audience is explicitly admitted.
2. Add `bridgesquad` to the production issuer's closed audience registry. Provision a unique production service proof via protected Vault/OCI operator procedures; never borrow another consumer's proof.
3. Audit all existing DNS/Pages entries. Explicitly refuse foreign/mismatched records and unexpected Pages aliases. Create a dedicated Cloudflare Pages project only through trusted Infra credentials. Deploy the reviewed edge Worker alongside a source-SHA-pinned copy of `index.html`, never anonymous static-only Pages.
4. Bind the app-only proof in the Pages **production** configuration, deny anonymous asset requests and all preview/production Pages aliases, and enable fail-closed on every route. Add the custom DNS only after readiness.
5. Live E2E: unauthenticated deny of root, HTML, assets, HEAD, and Pages aliases; actual account login, session renewal, logout and revocation; cross-audience/cross-environment negatives; separate account-local game progress; current main source SHA on mobile and desktop.
6. Retire any prior publicly accessible `evilsysadmin.github.io/matthias-bridge-squad/` deployment at cutover. A login on the custom domain is not protection if static content remains publicly served elsewhere.

This PR does not mutate Cloudflare, DNS, OCI, Vault, Identity runtime, or production. Do not claim the requested hostname live on the strength of these unit tests alone.

## Read-only Cloudflare discovery (no activation)

`scripts/bridgesquad_pages_readiness.py plan` prints fixed intended identities with no external calls. The `inspect` command uses only authenticated GET requests to Cloudflare's zone, the exact project `bridgesquad-production`, its exact custom domain, and the exact DNS record. It rejects foreign Pages source/branch/custom domains, ambiguous zone and DNS, unexpected aliases, and CNAME targets that differ from the owned project. It deliberately prints only `present/absent` and `not-verified`; this is never proof of signed-in delivery.

The workflow `Bridge Squad · production Pages inventory (read-only)` runs offline tests on PR/main. The inventory runs on trusted Infra `main` when this workflow or its audit contract changes, or via manual `workflow_dispatch` on `main` (never in PR). It uses the existing Cloudflare credential in the protected `staging` GitHub environment **strictly to perform GET-only zone/Pages/DNS reads**; it never uses staging Identity to authorize the production host and never writes to Cloudflare. If the protected environment requires approval, the inventory will remain pending until that approval. It does not enable the Identity audience or create DNS/Pages. If credentials are missing, inspect must fail, not assume resources are absent.

## Admisión SHA-pinned del artefacto de juego (sin desplegar)

El verificador `scripts/bridgesquad_source_admission.py` valida con GitHub, solo en lectura, el `main` actual de `evilsysadmin/matthias-bridge-squad`, una ejecución exitosa de `push` asociada a exactamente ese SHA y el paso **verde** de los dos jobs: `smoke` (Chromium desktop/móvil y 12 niveles) y `package-private-candidate`. Exige un artefacto único llamado `bridgesquad-private-release-<SHA>`, no caducado, con digest SHA-256 y vinculado a esa misma ejecución. Recomprueba `main` antes de admitirlo para evitar elegir una revisión antigua.

Para un ZIP descargado desde **ese ID exacto de artefacto**, `verify-archive ZIP sha256:DIGEST SHA` valida el digest del fichero comprimido y exclusivamente las dos entradas `index.html` y `release.json`, con límites de tamaño, sin symlinks ni ficheros adicionales. Comprueba el SHA-256 del HTML, la identidad del repositorio y el commit, `environment=production`, `audience=bridgesquad` y `authentication.required=true`. No extrae el ZIP ni incorpora un Worker proporcionado por el repositorio del juego. **Las etiquetas de autenticación de un manifiesto no proporcionan seguridad por sí mismas**.

El workflow `Bridge Squad · source release admission (read-only)` ejecuta todos los tests en PR y push. La tarea de inventario de GitHub para una versión actual se ejecuta **únicamente por dispatch manual desde Infra main**, y puede fallar por permisos de lectura entre repositorios. No escribe en Cloudflare, Identity, Vault ni DNS y no supone una publicación autorizada. El despliegue posterior deberá incluir el Worker auditado por Infra, verificar que el paquete descargado coincide con el recibo y probar acceso anónimo denegado y login/revocación reales. Seguimiento: #611.

## Paquete sellado por ShadowOps Infra (sin despliegue)

Después de admitir el SHA exacto mediante `bridgesquad_source_admission.py` y verificar independientemente el ZIP contra su digest GitHub, el operador puede preparar un directorio **nuevo** mediante:

```sh
python3 scripts/bridgesquad_release_package.py prepare candidato.zip sha256:<DIGEST_DEL_ZIP> <SHA_DEL_COMMIT> ./dist-sealed
python3 scripts/bridgesquad_release_package.py verify ./dist-sealed sha256:<DIGEST_DEL_ZIP> <SHA_DEL_COMMIT>
```

El empaquetador preserva sin reconstruir los bytes de `index.html`, descarta el manifiesto no confiable del juego después de validarlo y añade exclusivamente el `edge/bridgesquad-identity-gate.mjs` auditado por Infra como `_worker.js`. Genera un nuevo `release.json` con el digest del ZIP, SHA del origen y hashes del HTML y Worker, y rechaza symlinks, archivos extra, resultados manipulados o Workers diferentes de la versión auditada. Los tests de PR/main comprueban estas invariantes con ZIPs sintéticos, incluyendo escenarios de autenticación debilitada.

**Límite de confianza:** construir el directorio no prueba que GitHub haya autorizado ese ZIP, ni publica el dominio ni prueba login. El futuro workflow de publicación deberá exigir ambos recibos (metadatos GitHub actuales + ZIP validado), credenciales de producción protegidas, Cloudflare Pages configurado para **no servir estáticos sin Worker**, DNS con titularidad comprobada, y pruebas E2E sobre el host y aliases. No se permite usar staging Identity para el dominio de producción.

## Handoff automatizado de release sellado (sin desplegar)

El workflow `.github/workflows/bridgesquad-source-admission.yml` ahora prepara un artefacto **sin publicación** tras el paso de contratos, tanto en un `push` de Infra `main` como en un `workflow_dispatch` manual confiable. El job `sealed-candidate`:

1. Comprueba mediante la API de GitHub el `main` actual del juego, su CI `push`, los dos jobs requeridos y el ID/digest de un único artefacto.
2. Descarga ese **ID exacto** de GitHub Actions; verifica el SHA-256 del ZIP y el manifiesto de `index.html`.
3. Introduce el Worker de autenticación auditado por Infra y genera `release.json` propio; verifica los tres archivos contra los hashes calculados.
4. Revalida que el `main` del juego sigue siendo el mismo antes de archivar el paquete como `bridgesquad-sealed-<GAME_SHA>-<INFRA_SHA>` durante 14 días.

La ejecución no utiliza Cloudflare, DNS, OCI ni Vault. No despliega nada. Los artefactos de GitHub Actions **no deben tratarse como almacén de secretos**: contienen solo HTML/JavaScript y metadatos públicos. Si la identidad del artefacto ha cambiado o las credenciales de lectura GitHub no son válidas, el job falla sin producir un paquete.

Para el futuro despliegue es obligatoria una nueva comprobación de vigencia del SHA, integridad del paquete, identidad del Worker y despliegue fail-closed en Pages con prueba de login real. Este workflow **no resuelve** el bloqueo de Identity de producción registrado en #611.

## Alta del proyecto vacío de Pages (NO publica el juego)

El workflow `Bridge Squad · create empty fail-closed Pages project` crea únicamente el proyecto Direct Upload `bridgesquad-production` cuando el inventario anterior declara ausencia del proyecto, dominio y DNS, o comprueba la propiedad de un proyecto propio previamente creado. Se ejecuta exclusivamente desde `evilsysadmin/shadowops-infra/main` al fusionar estos contratos o mediante `workflow_dispatch`. Los PR ejecutan solo los tests.

El operador utiliza el entorno GitHub protegido `staging` **solo como custodio de la credencial de la misma cuenta Cloudflare**; esto NO conecta ShadowOps Identity staging al juego de producción. El cliente únicamente permite dos mutaciones exactas: `POST /accounts/{account}/pages/projects` para el nombre `bridgesquad-production` y `PATCH /accounts/{account}/pages/projects/bridgesquad-production` para desactivar `fail_open` en producción y previews, añadiendo la compatibilidad `global_fetch_strictly_public`. Nunca crea DNS, vincula un dominio, instala una credencial de Identity ni publica un archivo. Relee el proyecto después de la operación y falla si la política no coincide.

En este paso los recursos pueden quedar como `project=present domain=absent dns=absent`, lo que **no implica que el juego esté online**. Ante recursos ajenos, DNS huérfano, permisos Cloudflare insuficientes, o configuración incompatible, el workflow falla sin adoptar ni modificar esos recursos. La publicación futura y la prueba de acceso autenticado siguen condicionadas al Identity de producción (#611).

## Bootstrap único del bundle sellado en Pages sin dominio (inaccesible)

El workflow `Bridge Squad · one-time locked Pages alias bootstrap` tiene dos fases. Los PR ejecutan **solo contratos** (firma/identidad, admitencia del ZIP, hash del Worker y suites de errores). Una vez fusionado el cambio, y exclusivamente en un `push` del repositorio `evilsysadmin/shadowops-infra` a `main`, se permite un único intento de publicación en el proyecto Pages **ya creado** `bridgesquad-production` mediante la credencial Cloudflare custodiada en el entorno protegido.

Antes de tocar Pages exige el proyecto de Direct Upload propio, `fail_open=false` en `production` y `preview`, `global_fetch_strictly_public`, **sin custom domain, DNS, variables de entorno ni despliegues previos**. En paralelo, el juego debe tener una ejecución verde en su `main`, con el artefacto SHA-256 exacto. El deploy conserva el HTML original, lo empaqueta con el Worker auditado de Infra y escribe como `commit-hash` el SHA de origen. Revalida los dos `main` antes de hacer la **única operación de despliegue**: `wrangler pages deploy --project-name bridgesquad-production`. No crea secretos, no cambia DNS ni asocia el dominio.

Después de la entrega, reconsulta la configuración Cloudflare, el despliegue canónico de producción y su commit; prueba los hosts `*.pages.dev` que el proyecto declara (alias de proyecto y alias de despliegue) con solicitudes `GET`, `HEAD` y `POST` a raíz, HTML, release y rutas sensibles. **Solo acepta 404**. Si encuentra 200, redirección, 401, 503, un deployment de otro commit o cualquier incoherencia, el job falla. El upload nunca se interpreta como autorización de publicar el dominio. Intentos posteriores se bloquean cuando detectan cualquier deployment existente; las actualizaciones futuras necesitarán un release train distinto, aprobado y auditado.

Este bootstrap no debe confundirse con producción funcional. Aunque `index.html` esté instalado en Pages, su Worker rechaza todos los hosts de Pages y la URL pública `bridgesquad.shadowops.dpdns.org` permanece sin DNS ni vinculación. La activación productiva requiere **Identity independiente operativo**, audiencia y prueba propia en Vault, revocación/frescura, binding protegido, rechazo de acceso anónimo comprobado en el host canónico y finalmente pruebas reales de login y juego (issue #611).

## Vigilancia continua de aliases ya desplegados (sin escrituras)

El workflow `Bridge Squad · deployed alias security watchdog (read-only)` se ejecuta diariamente a las 07:31 UTC, por dispatch manual y después de fusionar sus propios cambios en Infra `main`. **Los PR solo ejecutan tests offline, sin credenciales.** La inspección protegida reutiliza la credencial de la cuenta Cloudflare en el entorno GitHub `staging` exclusivamente para efectuar GET y sondas HTTP a los aliases; no usa Identity staging para producción.

El watchdog inspecciona el `canonical_deployment` actual del proyecto, extrae su SHA de fuente, exige su coherencia con los metadatos canónicos de Pages, comprueba `fail_open=false` y configuración privada en ambos modos, y verifica que **no existan custom domain ni DNS** durante esta fase. Después prueba todos los aliases declarados, incluido el inmutable de deployment, con GET, HEAD y POST en raíz, HTML, release y rutas de sesión. Una respuesta distinta de 404 bloquea la auditoría; el nuevo cliente HTTP también exige el texto exacto `Not found` que devuelve el Worker para hosts ajenos (no acepta una página HTML genérica con código 404 como prueba de protección).

Esta vigilancia controla que el paquete desplegado no quede expuesto por accidente, pero **no sustituye** una prueba de login productivo ni autoriza la activación del dominio. Cuando Identity de producción esté disponible y se programe una publicación real, habrá que actualizar expresamente este contrato de preactivación para que supervise el host y las revocaciones reales, evitando alertas falsas durante el corte de DNS.

### Bootstrap retirado después de la primera entrega

El bootstrap de Pages tuvo éxito en [Actions run 44401118894](https://github.com/evilsysadmin/shadowops-infra/actions/runs/44401118894) y dejó dos aliases denegando invitados. Por eso su job de publicación se ha desactivado con una condición estática `false && ...`: modificaciones posteriores a código, documentos o contratos **no pueden volver a desplegar el juego por accidente**. Sus pruebas permanecen, pero cualquier release adicional deberá seguir un procedimiento de publicación nuevo, revisado y con Identity de producción previamente validado. El watchdog anterior asume desde ahora la vigilancia read-only de ese despliegue.

## Diagnóstico del emisor Identity de producción (sin activación)

El contrato `config/identity/platform-contract.json` reserva **solo en producción** el consumidor `audience=bridgesquad`, `origin=https://bridgesquad.shadowops.dpdns.org`, `status=not-provisioned`. Es una declaración de la identidad esperada, **no un registro ejecutable** ni un alta de usuarios, y no altera staging, las claves, las bases de datos, Vault ni el acceso al juego.

El workflow `Bridge Squad · production Identity public readiness (read-only)` prueba desde Infra `main`, sin credenciales, solo `https://id.shadowops.dpdns.org/readyz`, `/api/identity/jwks` y `/login?app=bridgesquad`. Rechaza redirecciones a staging, JWKS con claves privadas, algoritmos no permitidos o duplicados, ausencia de CSP en login y retorno que no esté fijado al host Bridge Squad. Ante fallos de DNS, TLS o 404/503, emite `not-ready`, sin afirmar que el emisor existe. Los PR ejecutan solo tests offline. No crea recursos ni envía contraseñas, tokens, cookies o POST.

El modo `inspect` es informativo: incluso si `public_surface=present`, siempre deja `service_proof=not-verified token_issuance=not-verified authorization=not-verified`. Un JWKS y una página de login **no prueban** sesiones, usuarios, revocación y secreto de consumidor. `require-public-surface` devuelve error si la superficie no existe; se puede usar como puerta para un futuro release, nunca como prueba completa de login.

Para activar `bridgesquad` realmente hay que construir y desplegar Identity productivo **separado** del servicio `cmd/service-staging` (que fija el host, las sesiones, la base de datos, el signer y el emisor a staging), con seeds, cuentas, sesiones y rol Mongo independientes; provisionar el secreto único de consumidor en Vault; emitir JWT EdDSA `iss=https://id.shadowops.dpdns.org`, `aud=bridgesquad` y validar su frescura contra el almacén de producción. Solo después se puede vincular el secreto a Cloudflare y activar DNS tras pruebas de sesión y revocación reales.
