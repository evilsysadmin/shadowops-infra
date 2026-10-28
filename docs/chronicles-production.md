# Chronicles · producción

Producción es igual que staging, con su propio estado. Nada se comparte salvo el host A1 y el wrapper root.

| | staging | production |
|---|---|---|
| Juego | https://staging.chronicles.shadowops.dpdns.org | https://chronicles.shadowops.dpdns.org |
| API | https://chronicles-api-staging.shadowops.dpdns.org | https://chronicles-api.shadowops.dpdns.org |
| Pages project | chronicles-staging | chronicles-production |
| Túnel | chronicles-staging | chronicles-production |
| Compose project / puerto | shadowops-chronicles-staging / 127.0.0.1:18081 | shadowops-chronicles-production / 127.0.0.1:18091 |
| Atlas DB | chronicles_staging | chronicles_production |
| Vault secret | chronicles-staging-runtime-env | chronicles-production-runtime-env |
| GitHub secrets | CHRONICLES_STAGING_* | CHRONICLES_PRODUCTION_* |

## Una sola vez (operador)

1. Atlas: usuario `chronicles_production` con rol propio `readWrite@chronicles_production`.
2. Secrets en `shadowops-infra` (entorno o repo): `CHRONICLES_PRODUCTION_MONGO_URL`,
   `CHRONICLES_PRODUCTION_JWT_SECRET`, `CHRONICLES_PRODUCTION_INVITE_CODE`.
3. Repetir el bootstrap one-shot sin argumentos (`host/bootstrap-chronicles-api-over-ssh.sh`)
   para instalar el wrapper que acepta entorno y el compose de producción.

## Release train diario (08:00 Europe/Madrid)


### Instalación controlada del Worker (todavía NO activada)

El workflow [`chronicles-scheduler-worker-rollout.yml`](../.github/workflows/chronicles-scheduler-worker-rollout.yml) proporciona una vía para validar el Worker y, más adelante, instalarlo **apagado**. La PR que introduce este flujo **no realiza por sí sola ningún despliegue**.

1. **Verificación sin Cloudflare:** desde GitHub Actions, ejecutar `Chronicles production scheduler · disabled Worker rollout` con `operation=verify`, o desde CLI: `gh workflow run chronicles-scheduler-worker-rollout.yml -R evilsysadmin/shadowops-infra --ref main -f operation=verify`. Se ejecutan los contratos de DST/configuración, se comprueba `SCHEDULER_ENABLED="false"` y `workers_dev=false`, y Wrangler realiza `deploy --dry-run` sin credenciales ni escritura externa.
2. **Inspección previa de Cloudflare (solo lectura):** una vez configurados `CLOUDFLARE_API_TOKEN` (permisos adecuados para consultar scripts Workers) y `CLOUDFLARE_ACCOUNT_ID` en el entorno protegido `production` de GitHub, ejecutar manualmente el workflow con `operation=inspect` en `main`. Este paso realiza exclusivamente un **GET autenticado del nombre exacto** `shadowops-chronicles-production-scheduler` y nunca ejecuta Wrangler ni publica nada. Solo termina verde si Cloudflare confirma un 404 (nombre libre); si el Worker ya existe, hay redirecciones, falta autenticación o el proveedor falla, bloquea sin sobrescribir. El job de `deploy_disabled` repite esta consulta justo antes de su eventual `wrangler deploy` para evitar una comprobación obsoleta. No publicar tokens ni cuerpos de respuesta.
3. **Instalación apagada (requiere intervención explícita y un `inspect` verde):** tras aprobar el entorno `production`, lanzar manualmente el mismo workflow con `operation=deploy_disabled`, `confirmation=DEPLOY_DISABLED_CHRONICLES_SCHEDULER` y ref `main`. Está prohibido en PR/push. Instala un Worker sin endpoint HTTP público y **con Cron triggers 06:00 y 07:00 UTC**, pero con `SCHEDULER_ENABLED=false`: cada invocación registra que sigue apagado y no llama a GitHub. Verificar esto en los eventos de Cron de Cloudflare; no confundirlo con una promoción.
4. **Activación posterior, como cambio independiente:** provisionar el secreto interactivo `GH_ACTIONS_TOKEN` restringido al repositorio, habilitar/validar el guard de duplicados `CHRONICLES_TRAIN_DEDUPE_ENABLED=true`, revisar el rollback, y solo entonces cambiar `SCHEDULER_ENABLED` a `true` mediante una PR distinta. Verificar un run real, su ID, admisión, SHA y auditoría; después retirar el cron GitHub de las 08:00. No abrir una ventana en la que dos fuentes primarias puedan publicar sin guard.
5. **Reversión:** el workflow de `deploy_disabled` es **solo de primera instalación** y por seguridad rechaza sobrescribir un Worker existente. Para revertir una activación posterior, usar un procedimiento de rollback independiente y explícito que vuelva a desplegar una versión auditada con `SCHEDULER_ENABLED=false`, conservando la evidencia; restaurar el cron GitHub si se hubiese retirado. Los jobs de producción ya iniciados requieren evaluación explícita: deshabilitar el Worker no cancela ni revierte un despliegue.

El pipeline sigue requiriendo las mismas validaciones de SHA, CI, recibos y salud de producción. El `schedule` de GitHub puede retrasarse; la instalación apagada no garantiza ni un minuto de puntualidad. El token del Worker **no** se envía al juego ni se muestra en logs.


### Protección de duplicados del release train (preparada, sin activar)

El tren serializa sus ejecuciones en GitHub y dispone ahora de una segunda protección de *solo lectura* para la coexistencia temporal entre el cron de GitHub y el disparador Cloudflare. **Por defecto está desactivada**: variable de repositorio `CHRONICLES_TRAIN_DEDUPE_ENABLED` sin valor o `false`. No habilitar antes del cutover validado. Con valor `true`, el job de promoción automática comprueba antes de tocar producción las ejecuciones del día según `Europe/Madrid` y la identidad real del workflow: incluye `schedule` y `workflow_dispatch` explícitamente `external-schedule`, nunca hotfixes manuales normales.

Si ya hubo una ejecución automática ese día, solo termina sin desplegar cuando el run anterior está en verde y su **job y paso reales de promoción** constan como completados correctamente. Si fue fallido, cancelado o no verificable, **falla cerrado** (no reintenta a ciegas); la recuperación queda bajo el flujo manual. Si no hay historial fiable, la comprobación bloquea la promoción en lugar de asumir que es el primer tren. La bitácora del run duplicado identifica el ID anterior. Los hotfixes manuales y `dry_run` no pasan por este guard.

Durante una eventual activación, verificar en el mismo cambio operativo: variable del guard habilitada, credencial del Worker limitada, disparo externo verificable, y **solo una fuente primaria de programación**; el cron GitHub debe retirarse tras validar la sustitución, no antes. Conservar rollback y auditoría independiente. Esta protección no hace que GitHub arranque instantáneamente ni resuelve el drift API/Pages.


> **Preparación de disparador externo, sin activar (28/10/2026):** `workers/chronicles-production-scheduler/` contiene un Worker de Cloudflare con dos franjas UTC y comprobación de zona `Europe/Madrid`. Rechaza ejecuciones que lleguen más de **5 minutos tarde** (o con reloj inválido) para impedir promociones imprevistas a media tarde; un retraso debe investigarse, no despachar un deploy tardío. **Está deshabilitado (`SCHEDULER_ENABLED=false`)**, no está desplegado ni tiene secreto de GitHub. La auditoría de las 09:15 acepta ya los eventos `schedule` o un `workflow_dispatch` etiquetado exactamente `external-schedule` y creado entre 07:45 y 08:15 de Madrid; sigue comprobando que el job real terminó correctamente. El guard de duplicados está implementado, pero **aún falta activarlo** con la variable del repositorio, configurar un token de Actions de mínimo privilegio, desplegar el Worker y realizar la prueba operacional. El dispatch automático envía `automated=true` para mantener los mismos gates de salud de producción que `schedule`. Mientras tanto permanece el cron existente de GitHub y el watchdog puede reconocer tanto `schedule` como una ejecución externa acreditada; no considerar desplegado el backup externo.


- El workflow [Chronicles production · release train](../.github/workflows/chronicles-production-train.yml) se programa con `cron: '0 8 * * *'` y zona IANA `Europe/Madrid`; GitHub gestiona CET/CEST. Es un **horario solicitado**, no una garantía de ejecución al segundo (la cola de Actions puede retrasarlo).
- Cada mañana resuelve el **SHA real del manifiesto público de Pages staging**, no el último commit de `main`. Antes de promover, vuelve a consultar el **`/api/release.build` público de la API de staging** y exige que coincida: dos recibos históricos no bastan si la API ha cambiado desde entonces. Además exige checks de CI y ambos recibos staging exactos mediante `chronicles_production_admission.py`. Una promoción manual con SHA histórico explícito conserva la admisión de CI/recibos, sin exigir que ese SHA sea la revisión servida *ahora* por staging.
- Si producción ya sirve ese SHA con recibos válidos y API sana, no despliega nada. Si ese mismo SHA está degradado, **falla cerrado** en lugar de declarar éxito o forzar un despliegue. Si el candidato de las **08:00** es diferente, primero exige que la producción actual siga siendo accesible (HTTPS, assets JS/CSS, API health/ready/CORS y JWKS). Una incidencia anterior al release train bloquea la promoción automática **antes de despachar API**, preservando la posibilidad de un hotfix **manual explícito** para recuperar un servicio caído. Un cambio de SHA no constituye por sí solo una recuperación autorizada.
- Para una versión nueva, despacha el workflow de API con SHA exacto, espera a su **run ID devuelto por GitHub**, exige resultado verde, recibo producido **por ese mismo run ID** (no vale uno antiguo con el mismo SHA), health/ready/CORS **y `/api/release.build` público igual al SHA admitido**. Una API sana con una imagen vieja o sin identidad de build bloquea el tren; **solo entonces** despacha Pages y vuelve a exigir resultado verde, recibo del **run ID exacto** y auditoría pública exacta.
- Los despliegues siguen siendo propiedad exclusiva de sus dos workflows protegidos. El tren solo dispone de `actions: write` y `contents: read`; no recibe secretos Atlas/OCI/Cloudflare. Se serializan los trenes entre sí, y cada workflow hijo mantiene sus locks propios.
- Los runs y el SHA elegido se registran en un artefacto JSON del train (90 días), **incluso si falla**: conserva etapa alcanzada y los IDs exactos de los workflows hijos, sin almacenar tokens ni respuestas privadas. Si falla Pages después de API, el registro indica el despliegue parcial; **no** se toca Mongo ni se aplica un rollback ciego: requiere intervención y comprobación de compatibilidad de datos.
- Producción requiere el entorno de GitHub `production`; si se configuran aprobaciones, se respetarán antes de ejecutar el train.

### Simulacro de admisión (sin desplegar nada)

Antes de la primera promoción automática, o para diagnosticar una versión candidata, ejecutar el modo de **solo lectura**. Usa el mismo gate de CI y recibos de staging y contrasta la versión actual de producción; no ejecuta workflows hijos, no accede a OCI/Cloudflare/Atlas y no crea usuarios. El job usa solo `contents: read` y `actions: read`.

~~~bash
gh workflow run chronicles-production-train.yml \
  -R evilsysadmin/shadowops-infra --ref main -f dry_run=true
~~~

También admite `-f source_sha='<SHA_COMPLETO_ACREDITADO>'` para inspeccionar una versión anterior acreditada. La ejecución registra `unchanged` o `would-promote` con SHA en un artefacto JSON de 30 días. Si el SHA no cambia, exige la auditoría pública completa. Si el candidato cambia, verifica que **la producción actual** siga sirviendo HTTPS, JS/CSS, API health/ready/CORS y JWKS público de Chess Studio, sin exigir que el binario antiguo tenga ya el SHA nuevo ni que se hayan generado recibos nuevos; un fallo bloquea el simulacro en vez de prometer una promoción segura. **Un preflight verde no sustituye al primer tren real ni al SSO de usuario.**

### Promoción fuera del horario (hotfix)

Por defecto una ejecución manual del tren usa el SHA acreditado actualmente visible en staging. Para una revisión histórica ya acreditada puede indicarse su SHA completo:

~~~bash
gh workflow run chronicles-production-train.yml \
  -R evilsysadmin/shadowops-infra --ref main
gh workflow run chronicles-production-train.yml \
  -R evilsysadmin/shadowops-infra --ref main \
  -f source_sha='<SHA_COMPLETO_ACREDITADO>'
~~~

El rollback sigue siendo **manual y explícito** mediante los workflows de API y Pages descritos más abajo; no se confunde con una promoción normal del train. SSO real y restauración de backups siguen siendo pruebas independientes y pendientes.

## Promoción (procedimiento manual de recuperación/hotfix, nunca en push)

1. `Chronicles API` → `provision`, environment `production`.
2. `Chronicles API` → `deploy`, environment `production`, `source_sha` = SHA validado en staging.
3. `Chronicles Pages release` → environment `production`, `source_sha` = el mismo SHA.
   La admisión exige que el SHA esté en `main` protegido; el build falla si apunta a la API de staging.

### Evitar un falso verde de staging al recuperar Pages

**Importante:** el formulario manual de `chronicles-pages-release.yml` tiene `environment=staging` como valor predeterminado. Al hacer una recuperación **solo de Pages en producción**, elegir explícitamente **production** e indicar el SHA completo del backend que ya responde por `/api/release`. De otro modo, un run de staging puede terminar verde aunque el job de producción esté *skipped*.

La validación temprana `chronicles_pages_manual_target.py` ahora rechaza un `source_sha` suministrado con `environment=staging` en modo manual normal; exige `environment=production` y SHA exacto para la promoción. Las sincronizaciones internas de staging con `only_if_new=true` mantienen el SHA como mecanismo de control y no cambian. Un workflow rojo por selección ambigua **no prueba una incidencia en producción** ni autoriza nuevos despliegues.

Ejemplo de recuperación **dirigida exclusivamente a Pages**, sujeto a CI, recibos y guardas de producción:

~~~bash
gh workflow run chronicles-pages-release.yml \
  -R evilsysadmin/shadowops-infra --ref main \
  -f environment=production \
  -f source_sha='03e8f308a701e2df1c30d5e1259330a477a4ade3'
~~~

Después, exigir que el job **«Promote a Chronicles main SHA to production»** termine verde, comprobar los recibos de API y Pages de producción, y ejecutar una nueva auditoría independiente desde `main`. Un `success` global con ese job omitido no cuenta como recuperación.

## Puerta de promoción (control previo a mutaciones)

- Indicar siempre el SHA completo; no se puede usar un `source_sha` vacío en producción.
- Exigir **ambos** recibos verificados y vigentes del mismo SHA: `chronicles-api-staging-<sha>` y `chronicles-pages-staging-<sha>`, de workflows correctos completados con éxito en `shadowops-infra/main`.
- Volver a exigir los tres checks reales de CI de `chronicles-of-matthias` para ese SHA y que el commit pertenezca al historial de `main` protegido.
- Estos recibos prueban generaciones históricas validadas, **no** que staging siga sirviendo hoy ese SHA; consultar el manifiesto público antes de elegir candidato.
- El gate es de solo lectura y se ejecuta antes de cualquier mutación OCI de producción; un recibo ausente, fallido o caducado bloquea el despliegue.
- La promoción real queda bloqueada hasta completar secretos, Atlas, bootstrap del host, Cloudflare y validación de producción; CI verde por sí sola no demuestra un despliegue.

## Primera release verificada — 20/10/2026

- SHA fuente: 43ffecf5779dc9124bdd0dbc05a3a34e29044c9b (v16.6dm46zfrv), no confundir con SHA de Infra.
- Staging, mismo SHA: [API #39497113941](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39497113941) y [Pages #39497117194](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39497117194), ambos recibos vigentes en la promoción.
- Preparación producción: [provision #39498706525](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39498706525).
- API producción: [deploy #39500699825](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39500699825), health/ready y artefacto chronicles-api-production-43ffecf5779dc9124bdd0dbc05a3a34e29044c9b.
- Pages producción: [release #39504855366](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39504855366), HTTPS, juego, manifest SHA y artefacto chronicles-pages-production-43ffecf5779dc9124bdd0dbc05a3a34e29044c9b.
- **Límite de la evidencia:** estos recibos acreditan despliegue técnico, no todavía SSO de usuario real, compras, combates, guardado/recarga ni restauración de Atlas.

### Cierre funcional (manual; no publicar credenciales)

1. En ventana privada, abrir https://chronicles.shadowops.dpdns.org, iniciar sesión mediante **Chess Studio producción** y comprobar logout. Revisar red y CORS; ninguna petición debe apuntar a staging.
2. Crear personaje/campaña, comprar, combatir, guardar, recargar y continuar. Desde nueva sesión del mismo usuario comprobar persistencia y, con un usuario distinto, comprobar aislamiento.
3. Repetir la ruta principal en móvil y comprobar que no hay 401/5xx, assets ausentes ni errores de consola.
4. Verificar por vía administrativa que el usuario Atlas producción solo tiene readWrite@chronicles_production; demostrar separación de staging y Chess Studio. No publicar datos personales ni tokens.
5. Registrar fecha, SHA, navegador y resultados redactados en [issue #102](https://github.com/evilsysadmin/shadowops-infra/issues/102). **No** marcar estos checks completados sin haberlos ejecutado.

### Lectura de un fallo de SHA en producción

La auditoría de producción conserva el código fijo `CHRONICLES_PRODUCTION_AUDIT_BLOCKED stage=api_sha`. Cuando el motivo es que la API y Pages sirven **SHA distintos**, añade una línea `CHRONICLES_PRODUCTION_SHA_MISMATCH pages=<SHA> api=<SHA|unavailable>`. Ambos identificadores se leen de endpoints públicos y se validan como SHA completos antes de mostrarlos: jamás se publican cuerpos de respuesta, tokens ni errores del proveedor. Si la API no ofrece un SHA válido, aparece `unavailable`.

Después de un despliegue parcial, usar este dato únicamente para orientar **una recuperación manual protegida**: verificar salud, compatibilidad, staging acreditado y recibos exactos antes de decidir entre publicar Pages para el SHA de API o revertir API al SHA servido por Pages. No relanzar automáticamente el tren ni fusionar cambios de Infra con un tren en marcha.

### Auditoría tras el tren y control diario

Además de `workflow_dispatch`, el auditor se ejecuta en un **push a `main` solo cuando cambia `scripts/chronicles_production_audit.py` o su propio workflow**. Esta comprobación es exclusivamente de lectura y publica en GitHub Actions los códigos `stage=...` y, si procede, el par de SHA públicos de API y Pages. Las PR ejecutan únicamente pruebas offline; este disparo acotado evita confundir CI de PR con observabilidad de producción. Un resultado rojo NO autoriza una promoción o rollback automáticos.


Además del simulacro y del smoke incluido en el release train, el workflow independiente `chronicles-production-audit.yml` vuelve a comprobar producción **cuando termina cualquier train** (`workflow_run: completed`, incluido uno fallido, para detectar promociones parciales). Tiene además un chequeo diario de respaldo a las **09:15 Europe/Madrid** con cambio CET/CEST automático, y conserva el disparo manual. Nunca despliega ni escribe datos. El control de las 09:15 ejecuta dos jobs independientes: uno audita HTTPS/API/recibos y otro busca un evento `schedule` legítimo o un `workflow_dispatch` externo etiquetado explícitamente `external-schedule`, creado **hoy entre las 07:45 y las 08:15 Madrid** si es externo (o desde las 07:45 para `schedule`), mediante GitHub Actions con permisos de solo lectura. El segundo job requiere que el **último run programado de hoy** haya terminado con conclusión `success`, y además confirma mediante GitHub Actions que el job **«Admit staging, promote API, promote Pages, verify public release»** y su paso de promoción se ejecutaron y terminaron correctamente. Un workflow global verde con ese job omitido no basta: distingue un tren omitido (`NOT_OBSERVED`), todavía en cola/ejecución (`INCOMPLETE`) y fallido o cancelado (`FAILED`). Así no informa de éxito solo porque se creó el run, ni porque la producción anterior siga sana. Si el tren está retrasado por GitHub o pendiente de aprobación a las 09:15, se trata como incidencia a investigar, sin autocorrección. El monitor no relanza ni cancela nada. Un resultado negativo requiere investigar el estado real, no relanzar a ciegas el tren o limpiar Mongo.

### Identidad del binario API en producción

Los recibos prueban qué imagen se desplegó, pero **no** qué contenedor responde ahora por HTTPS. Por eso la auditoría de producción compara `https://chronicles-api.shadowops.dpdns.org/api/release.build` (campo `build` del JSON en `/api/release`) contra el `build` de `https://chronicles.shadowops.dpdns.org/release.json`. El release train exige esa misma identidad **después de desplegar API y antes de lanzar Pages**.

Si el binario antiguo no incorpora todavía el SHA, o si Cloudflare sirve una revisión distinta, el control falla cerrado; no debe marcarse el estado como sano, ni inventar un SHA basándose en el artefacto histórico. No se revela ningún token ni se escribe nada.

El workflow de **Pages producción manual** aplica el mismo guard de lectura tres veces: tras comprobar recibos y salud, antes de la primera mutación de Cloudflare, inmediatamente antes de `wrangler pages deploy` y **después de verificar HTTPS y el manifest**, justo antes de emitir el recibo de producción. Así un operador que salte el release train no puede publicar un frontend incompatible con la API viva. La comprobación falla cerrado si `/api/release.build` no está disponible; hay que promocionar primero una API compatible y acreditada.

### Verificación de disponibilidad de SSO (sin credenciales)

El auditor de producción comprueba también el JWKS público de Chess Studio **producción** (`https://api.chess-studio.shadowops.dpdns.org/api/identity/jwks`): TLS/origen esperado, JSON bien formado, claves Ed25519 con `kid` único y clave pública de 32 bytes, sin material privado. No consulta Chess Studio staging ni crea cuentas o tokens. Su respuesta **no demuestra el login**, el intercambio real del JWT ni los permisos sobre una partida: esos pasos permanecen en el smoke manual de usuario y requieren evidencia separada.

### Smoke público sin acceso de usuario

~~~bash
curl -fsS https://chronicles-api.shadowops.dpdns.org/api/health
curl -fsS https://chronicles-api.shadowops.dpdns.org/api/ready
curl -fsS https://chronicles.shadowops.dpdns.org/release.json | python3 -m json.tool
~~~

El build de release.json debe coincidir con el SHA desplegado tanto en API como en Pages. Una portada que carga y un health 200 no prueban login, datos ni partida.

## Rollback: procedimiento manual, sin modificar MongoDB

Seleccionar un SHA anterior del juego que **ya** tenga checks de CI y recibos staging API/Pages correctos, pertenezca a main protegido y sea compatible con el esquema de datos actualmente persistido. No usar un SHA aleatorio ni confundir el SHA del repositorio Infra con el SHA del juego. No existe release anterior si solo ha habido un estreno.

~~~bash
SHA='<40_HEX_SHA_VERIFICADO_ANTERIOR>'
gh workflow run chronicles-api-staging.yml \
  -R evilsysadmin/shadowops-infra --ref main \
  -f action=deploy -f environment=production -f source_sha="$SHA"
# Exigir run de API verde, /api/health, /api/ready y recibo API prod.
gh workflow run chronicles-pages-release.yml \
  -R evilsysadmin/shadowops-infra --ref main \
  -f environment=production -f source_sha="$SHA"
# Exigir run de Pages verde, HTTPS y /release.json.build == SHA.
~~~

- Rollback **API primero, Pages después**, con el mismo SHA. No ejecutar promociones simultáneas. Revalidar SSO/partida después de volver atrás.
- No restaurar Mongo automáticamente: un rollback de binarios **no** revierte cambios de esquema ni datos. Ante migraciones incompatibles, detenerse y diseñar restauración de datos separada.
- Registrar SHA, digest de imagen API, recibos y URLs de runs de cada versión de producción. Comprobar que los artefactos necesarios no hayan caducado.
- Comprobar política real de backups y recuperación puntual (si está disponible) en Atlas. Hacer ensayo de **restore hacia una base aislada**, verificar integridad y medir RPO/RTO antes de considerar el sistema recuperable; jamás ensayar sobre producción.

## Diagnóstico y límites

- Gate API fallido: leer el paso exacto de admisión; no tocar los contenedores o secretos de Chess Studio.
- Gate Pages fallido: resolver mediante PR y un workflow nuevo desde main; no hacer rerun de un commit que contiene un bug conocido.
- Cloudflare Pages pending no basta: producción requiere HTTPS TLS válido, recursos HTML/JS/CSS reales y manifest público con SHA exacto.
- Incidencia de datos: congelar promociones, conservar logs redactados y estado actual, comprobar compatibilidad antes de cualquier cambio.
- No dar por cerrada la activación hasta tener **smoke funcional y ensayo de backup/restore**. El despliegue técnico sí quedó verificado.
