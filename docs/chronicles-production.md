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

- El workflow [Chronicles production · release train](../.github/workflows/chronicles-production-train.yml) se programa con `cron: '0 8 * * *'` y zona IANA `Europe/Madrid`; GitHub gestiona CET/CEST. Es un **horario solicitado**, no una garantía de ejecución al segundo (la cola de Actions puede retrasarlo).
- Cada mañana resuelve el **SHA real del manifiesto público de staging**, no el último commit de `main`. Exige checks de CI y ambos recibos staging exactos mediante `chronicles_production_admission.py` antes de promover.
- Si producción ya sirve ese SHA con recibos válidos y API sana, no despliega nada. Si ese mismo SHA está degradado, **falla cerrado** en lugar de declarar éxito o forzar un despliegue.
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

También admite `-f source_sha='<SHA_COMPLETO_ACREDITADO>'` para inspeccionar una versión anterior acreditada. La ejecución registra `unchanged` o `would-promote` con SHA en un artefacto JSON de 30 días; fallará si la versión que ya sirve producción está degradada, no tiene recibos fiables o su juego público falla la auditoría. **Un preflight verde no sustituye al primer tren real ni al SSO de usuario.**

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

### Auditoría tras el tren y control diario

Además del simulacro y del smoke incluido en el release train, el workflow independiente `chronicles-production-audit.yml` vuelve a comprobar producción **cuando termina cualquier train** (`workflow_run: completed`, incluido uno fallido, para detectar promociones parciales). Tiene además un chequeo diario de respaldo a las **09:15 Europe/Madrid** con cambio CET/CEST automático, y conserva el disparo manual. Nunca despliega ni escribe datos. Un resultado negativo requiere investigar el estado real, no relanzar a ciegas el tren o limpiar Mongo.

### Identidad del binario API en producción

Los recibos prueban qué imagen se desplegó, pero **no** qué contenedor responde ahora por HTTPS. Por eso la auditoría de producción compara `https://chronicles-api.shadowops.dpdns.org/api/release.build` (campo `build` del JSON en `/api/release`) contra el `build` de `https://chronicles.shadowops.dpdns.org/release.json`. El release train exige esa misma identidad **después de desplegar API y antes de lanzar Pages**.

Si el binario antiguo no incorpora todavía el SHA, o si Cloudflare sirve una revisión distinta, el control falla cerrado; no debe marcarse el estado como sano, ni inventar un SHA basándose en el artefacto histórico. No se revela ningún token ni se escribe nada.

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
