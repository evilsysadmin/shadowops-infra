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

Para el ZIP **reconstruido de manera independiente por Infra a partir de los bytes públicos del commit exacto**, `verify-archive ZIP sha256:DIGEST SHA` valida el digest del fichero comprimido y exclusivamente las dos entradas `index.html` y `release.json`, con límites de tamaño, sin symlinks ni ficheros adicionales. El artefacto original de Actions sigue siendo evidencia de CI: su digest NO es el del ZIP reconstruido. Comprueba el SHA-256 del HTML, la identidad del repositorio y el commit, `environment=production`, `audience=bridgesquad` y `authentication.required=true`. No extrae el ZIP ni incorpora un Worker proporcionado por el repositorio del juego. **Las etiquetas de autenticación de un manifiesto no proporcionan seguridad por sí mismas**.

El workflow `Bridge Squad · source release admission (read-only)` ejecuta todos los tests en PR y push. La tarea de inventario de GitHub para una versión actual se ejecuta **únicamente por dispatch manual desde Infra main**, y puede fallar por permisos de lectura entre repositorios. No escribe en Cloudflare, Identity, Vault ni DNS y no supone una publicación autorizada. El despliegue posterior deberá incluir el Worker auditado por Infra, verificar que el paquete descargado coincide con el recibo y probar acceso anónimo denegado y login/revocación reales. Seguimiento: #611.

## Paquete sellado por ShadowOps Infra (sin despliegue)

Después de admitir el SHA exacto mediante `bridgesquad_source_admission.py`, `bridgesquad_source_snapshot.py snapshot SHA candidato.zip` descarga `index.html` del SHA inmutable en GitHub Raw y crea un ZIP privado con manifiesto Infra (sin token Actions ajeno). Tras verificar ese ZIP contra su **digest local**, el operador puede preparar un directorio **nuevo** mediante:

```sh
python3 scripts/bridgesquad_release_package.py prepare candidato.zip sha256:<DIGEST_DEL_ZIP> <SHA_DEL_COMMIT> ./dist-sealed
python3 scripts/bridgesquad_release_package.py verify ./dist-sealed sha256:<DIGEST_DEL_ZIP> <SHA_DEL_COMMIT>
```

El empaquetador preserva sin reconstruir los bytes de `index.html`, descarta el manifiesto no confiable del juego después de validarlo y añade exclusivamente el `edge/bridgesquad-identity-gate.mjs` auditado por Infra como `_worker.js`. Genera un nuevo `release.json` con el digest del ZIP, SHA del origen y hashes del HTML y Worker, y rechaza symlinks, archivos extra, resultados manipulados o Workers diferentes de la versión auditada. Los tests de PR/main comprueban estas invariantes con ZIPs sintéticos, incluyendo escenarios de autenticación debilitada.

**Límite de confianza:** construir el directorio no prueba que GitHub haya autorizado ese ZIP, ni publica el dominio ni prueba login. El futuro workflow de publicación deberá exigir ambos recibos (metadatos GitHub actuales + ZIP validado), credenciales de producción protegidas, Cloudflare Pages configurado para **no servir estáticos sin Worker**, DNS con titularidad comprobada, y pruebas E2E sobre el host y aliases. No se permite usar staging Identity para el dominio de producción.

## Handoff automatizado de release sellado (sin desplegar)

El workflow `.github/workflows/bridgesquad-source-admission.yml` ahora prepara un artefacto **sin publicación** tras el paso de contratos, tanto en un `push` de Infra `main` como en un `workflow_dispatch` manual confiable. El job `sealed-candidate`:

1. Comprueba mediante la API de GitHub el `main` actual del juego, su CI `push`, los dos jobs requeridos y el ID/digest de un único artefacto.
2. **No descarga ese artefacto privado del otro repositorio:** obtiene `index.html` desde GitHub Raw a la referencia SHA de ese mismo `main` y crea un ZIP privado con `release.json` generado por Infra, SHA-256 local y validación íntegra. El ID/digest original de Actions se conserva solo como prueba de CI verde, nunca se confunde con el nuevo ZIP.
3. Introduce el Worker de autenticación auditado por Infra y genera `release.json` propio; verifica los tres archivos contra los hashes calculados.
4. Revalida que el `main` del juego sigue siendo el mismo antes de archivar el paquete como `bridgesquad-sealed-<GAME_SHA>-<INFRA_SHA>` durante 14 días.

La ejecución no utiliza Cloudflare, DNS, OCI ni Vault. No despliega nada. Los artefactos de GitHub Actions **no deben tratarse como almacén de secretos**: contienen solo HTML/JavaScript y metadatos públicos. Si la identidad del artefacto CI ha cambiado, la evidencia pública es inaccesible o el SHA del código descargado no cumple el contrato, el job falla sin producir un paquete.

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

## Dominio accesible en cuarentena (sin habilitar el juego)

Por petición explícita de adelantar **la accesibilidad del DNS**, se permite una excepción controlada al orden del *release train* original: registrar `bridgesquad.shadowops.dpdns.org` en el Pages **ya desplegado y sellado**, sin utilizar Identity de staging y **sin instalar todavía la credencial de Identity de producción**. Esto NO es un despliegue funcional de Bridge Squad.

El workflow `Bridge Squad · activate DNS quarantine (auth required, game locked)` solo se ejecuta con credenciales desde `evilsysadmin/shadowops-infra/main`, bajo el entorno GitHub protegido que custodia las credenciales existentes de la cuenta Cloudflare. Los PR ejecutan pruebas offline. Comprueba primero el Worker ya desplegado, el SHA inmutable del juego, `fail_open=false` en producción y previews, **ninguna variable de entorno/secret de Identity**, los dos aliases `*.pages.dev` devolviendo HTTP 404, y propiedad exacta de proyecto/zona. Solo permite dos escrituras, con comprobación de lectura tras cada una: asociar **este** hostname a `bridgesquad-production` y crear **este** CNAME con `proxied=true` hacia `bridgesquad-production.pages.dev`. Los DNS de terceros, las colisiones y los proyectos extraños bloquean toda operación.

La prueba final exige resolución DNS, HTTPS/TLS válido, `GET /` y `GET /index.html` devolviendo **401 con la pantalla de ShadowOps ID** (nunca el HTML Canvas), y `GET /release.json`, `GET /_worker.js` y `GET /api/bridgesquad/session` devolviendo `401 authentication_required`. `HEAD` debe estar protegido y todos los aliases Pages deben seguir respondiendo 404 del Worker. Si Cloudflare demora el certificado o existe una fuga de archivos, el job **falla** y no se anuncia el dominio como listo. El watchdog diario ahora comprueba el mismo contrato cuando el DNS ya existe.

**Límite estricto:** tener el dominio accesible no significa poder iniciar sesión ni jugar. El emisor `id.shadowops.dpdns.org` permanece sin provisionar; el enlace de login puede fallar hasta disponer de Identity productivo, cuentas, tokens, comprobación de frescura y revocación. **Prohibido** convertir el enlace a staging, desactivar el Worker o servir el juego anónimamente para resolverlo. La siguiente fase activará la credencial productiva y sustituirá el contrato de cuarentena por pruebas completas de usuario autenticado antes de anunciar un lanzamiento jugable. Seguimiento #287 y #611.

## Chromium production Identity login E2E aislado (sin despliegue)

El workflow de réplica efímera de Identity añade
`TestChromiumProductionBridgeSquadJourney`, que arranca las rutas
**reales** de login de producción, sesiones nativas en Mongo local de pruebas,
firma JWT Ed25519, JWKS, CORS, cookies HTTPS host-only y comprobación
transaccional de frescura. Chromium recorre dos tamaños de pantalla (desktop y
móvil), entra en `id.shadowops.dpdns.org`, vuelve a
`bridgesquad.shadowops.dpdns.org`, comprueba el intercambio de token
`aud=bridgesquad`, verifica la firma con JWKS y prueba que logout invalida
la sesión y el JWT existente.

Ambos dominios se resuelven **solo dentro del navegador del runner**, hacia
`127.0.0.1:19444`; las rutas de Identity usan un servidor TLS real con
certificado efímero. El consumidor web de prueba es **HTML sintético** para
probar las reglas de navegador: **no es** el bundle del juego, ni el Worker
Cloudflare real, ni la cuenta productiva ni el DNS público. La suite no
provisiona secretos, no modifica OCI, Mongo externo ni Cloudflare. La prueba
HTTP + firma real del Worker sigue en
`tests/bridgesquad-identity-gate.test.mjs`, separada de esta prueba.

El E2E real del host publicado, con autenticación productiva, despliegue Pages,
revocación vía edge y prueba jugable, sigue siendo obligatorio antes de retirar
el estado 401. Ver #611.

## Entrega privada automática al actualizar Bridge Squad (sin despliegue)

El pipeline **Bridge Squad · source release admission (read-only)** comprueba
una vez al día (`07:19 UTC`) la rama `main` del juego y los
checks reales de su candidato privado, además de reaccionar a cambios
auditados en el propio Infra y permitir lanzamiento manual desde Infra main.
El calendario no instala un token de cross-repo ni ejecuta un webhook externo.
El permiso GitHub `actions: read` se usa exclusivamente para leer
metadatos de CI y descargar el artefacto del juego **después de admitir**
su SHA/digest y origen.

Para no crear artefactos repetidos cada día, el workflow inspecciona en
**solo lectura** los candidatos sellados del propio Infra y acepta
una coincidencia únicamente si el nombre contiene exactamente los SHAs
del juego y de Infra, el digest y el tamaño son válidos, el run pertenece
a la rama main de Infra y **el workflow anterior ha terminado en verde**.
Un run incompleto o fallido no cancela un nuevo intento; un metadato
inconsistente bloquea la entrega, y un artifact caducado no cuenta.
La política está probada con datos sintéticos en
`tests/test_bridgesquad_sealed_candidate_dedupe.py`.

Si hay un nuevo SHA verde del juego se vuelve a admitir la procedencia,
verificar el ZIP por SHA-256, sellar sus bytes con el Worker auditable de
Infra y publicar **solo** un artifact privado de GitHub Actions, sin
enlazar DNS, sin subir a Cloudflare Pages y sin habilitar el dominio.
Un `sealed-candidate` representa un candidato disponible para revisión,
**nunca** un permiso de promoción ni una prueba de sesión real.

## Navegador contra el paquete realmente sellado (CI aislada)

El handoff privado ahora valida el **directorio sellado exacto**, antes de
archivarlo, con Chromium y el Worker de Infra que se va a incluir en Pages.
La prueba no copia la lógica de autorización: lee el archivo _worker.js
del paquete, comprueba su digest contra release.json y ejecuta el handler
real con WebCrypto Ed25519 y respuestas sintéticas de JWKS y freshness.

En un navegador aislado, la prueba usa el host canónico para comprobar
que el invitado obtiene 401 en raíz y manifiesto, que los aliases Pages
siguen cerrados con 404, que una cuenta sintética con cookie HttpOnly de
Identity intercambia un JWT EdDSA por una cookie del Worker, que el HTML
**real del juego** carga y comienza una misión en 390 × 844 y
1440 × 900, que la renovación no interrumpe la partida, y que la
revocación posterior cierra tanto el acceso a assets como la partida.

Toda solicitud del navegador se intercepta y resuelve en una pasarela
**127.0.0.1** sin peticiones a DNS, Cloudflare o Identity productivo.
Solo el artefacto juego/Worker es real; las claves, sesiones y cuenta
son **efímeras y sintéticas**. La CI del PR prueba el Worker real contra
HTML sintético y verifica los contratos de encadenamiento; la prueba de
Chromium sobre HTML de release se ejecuta en el job sealed-candidate
de main de Infra **solo para artefactos nuevos**. Si falla, el paquete
no se archiva.

Esto **no** acredita un login productivo real, secretos del consumidor,
R2/Pages, configuración de DNS ni una partida completa de doce niveles
en la URL real. El smoke determinista de los doce niveles sigue en el
repositorio del juego; para quitar el HTTP 401 se necesita todavía el
E2E autenticado contra los recursos productivos custodiados.

## Ruta staging con ShadowOps ID staging (decisión 25-11-2026)

Para poder jugar sin esperar al Identity productivo (#611), Bridge Squad sigue
el mismo patrón que Football, Snooker y Star Adventures: host propio
`https://staging.bridgesquad.shadowops.dpdns.org`, emisor
`https://id-staging.shadowops.dpdns.org` y audiencia `bridgesquad` **solo en
staging**. El nombre de audiencia coincide con el reservado en producción, pero
los entornos siguen aislados: emisor, origen, cookie, claves de firma, base de
datos y proof `soc1_` distintos. El host de producción
`bridgesquad.shadowops.dpdns.org` **no cambia**: sigue en cuarentena 401 y
nunca aceptará tokens de staging.

**Iteración 1 (esta PR): registro del consumidor, default-off.** El código de
Identity staging reconoce `bridgesquad` y su origen exacto; login y CORS solo
se habilitan si el runtime tiene el proof explícito. El bundle de operador
añade un proof único solo con `identity-staging-operations.yml`,
`action=provision`, `bridgesquad_consumer=enable` (por defecto `preserve`).
No cambia Cloudflare, DNS, Pages, Vault ni el runtime en vivo.

Siguientes iteraciones:

1. Derivar la configuración Atlas aislada del candidato con `bridgesquad`
   (como `identity_staging_atlas_staradvs_config.py`) y liberar la imagen de
   Identity staging con rollback a la config original.
2. Worker staging (`edge/bridgesquad-staging-identity-gate.mjs`): host
   `staging.bridgesquad…`, `iss=id-staging`, `aud=bridgesquad`, aliases 404.
3. Proyecto Pages `bridgesquad-staging`, release sellado SHA-pinned desde el
   `main` verde del juego, binding `SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL`
   y CNAME proxied tras verificar invitado denegado.
4. E2E real: login, partida en móvil/escritorio, renovación, logout/revocación.

## Staging Pages + DNS en un clic (`bridgesquad-staging.yml`)

Workflow **Bridge Squad · staging behind ShadowOps ID (one-click)**, solo por
dispatch manual desde `main`, en el entorno protegido `staging`:

```sh
gh workflow run bridgesquad-staging.yml -R evilsysadmin/shadowops-infra --ref main -f action=activate
```

`activate` es idempotente y sirve también para publicar un SHA nuevo del juego:

1. Admite el `main` verde actual del juego (o `game_sha`) y sella `index.html`
   de ese commit exacto con el Worker auditado
   `edge/bridgesquad-staging-identity-gate.mjs` (`iss=id-staging`,
   `aud=bridgesquad`, host exacto, aliases `*.pages.dev` → 404).
2. Crea o verifica el proyecto Pages **dedicado** `bridgesquad-staging`, con
   `fail_open=false` en producción y en previews. Nunca adopta recursos ajenos ni DNS huérfano.
3. Despliega solo el paquete sellado, comprueba el SHA canónico y que **todos**
   los aliases devuelven el 404 del Worker.
4. Vincula `SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL` (secret_text, solo en
   producción) desde el bundle de Vault del operador. Si aún no existe
   (`bridgesquad-activate` de Identity no se ha ejecutado), informa
   `PROOF_PENDING` y sigue cerrado.
5. Solo después asigna `staging.bridgesquad.shadowops.dpdns.org` (dominio +
   CNAME proxied a `bridgesquad-staging.pages.dev`).
6. Audita HTTPS real: `/` y `/index.html` → 401 con el shell de login de
   `id-staging`, assets/API → 401 JSON, HEAD → 401, aliases → 404.

`inspect` y `audit` son de solo lectura. El host de producción
`bridgesquad.shadowops.dpdns.org` y su proyecto no se tocan.

Orden recomendado: `identity-staging-operations.yml action=bridgesquad-activate`
(audiencia y proof) → `bridgesquad-staging.yml action=activate`. En el orden
inverso también es seguro: el juego queda cerrado hasta que se vincule el proof
(volver a lanzar `activate`). Falta el E2E real con cuenta: login, partida,
renovación y logout.
