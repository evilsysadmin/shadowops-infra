# Matthias Bridge Squad · promoción protegida del juego a producción

Este release train publica exclusivamente en **Cloudflare Pages**, bajo el proyecto `bridgesquad-production`. GitHub proporciona repositorios y artefactos CI; **GitHub Pages no forma parte del alojamiento**. El proceso **no**
genera cuentas, credenciales, DNS, Identity productivo ni secretos. La
preparación ocurre sin acceso a Cloudflare; la promoción es una decisión
**manual** del operador, nunca un push automático de juego o Infra.

Workflow: `.github/workflows/bridgesquad-production-release.yml`.
El operador dispara **Run workflow** desde `shadowops-infra/main` con:

- `target_sha`: SHA completo actual del `main` de
  `evilsysadmin/matthias-bridge-squad`, cuya CI Chromium y empaquetado están verdes.
- `expected_live_sha`: SHA completo publicado actualmente en el proyecto
  Cloudflare Pages `bridgesquad-production`, obtenido de su
  `canonical_deployment` (no del `main` del juego).
- `confirm`: exactamente `RELEASE_BRIDGESQUAD_PRODUCTION`.

La etapa **prepare** exige una ejecución push verde del juego y verifica
el ID/digest **como evidencia de CI**, sin intentar descargar ese artefacto
privado de un repositorio ajeno con el `GITHUB_TOKEN` de Infra (que no concede
permisos Actions de otro repositorio). En su lugar descarga únicamente los
bytes de `index.html` desde `raw.githubusercontent.com` fijados a ese
**mismo commit SHA**, sin credenciales, y el empaquetador controlado por Infra
reconstruye `release.json` y un ZIP privado de dos entradas. Verifica el
SHA-256 del ZIP reconstruido, el manifiesto, `index.html`, y añade el
`_worker.js` auditado por Infra. El digest del paquete reconstruido NO se
confunde con el digest original de la evidencia CI. Chromium prueba el Worker
real sellado con Ed25519 sintético, login, renovación, revocación y aliases 404.
Recomprueba `main` del juego y de Infra. El candidato no lleva secretos,
caduca tras un día y **solo se entrega a Cloudflare Pages bajo el flujo
protegido**. En PR se ejecutan únicamente contratos sin credenciales.

La etapa **publish** requiere el entorno GitHub
`bridgesquad-production`, con **revisores obligatorios** configurados
expresamente por un administrador y los secretos
`CLOUDFLARE_ACCOUNT_ID` y `CLOUDFLARE_API_TOKEN` limitados al
entorno para el proyecto Pages exacto. No reutilizar el entorno
`staging` ni credenciales de ShadowOps Identity staging. Configurar
también la política de restricciones de ramas a `main`. GitHub puede crear
entornos sin protección al mencionarlos en un workflow: la existencia del
nombre **no** demuestra que los revisores y las restricciones estén activos.
El administrador debe revisar los controles antes de ejecutar el primer
dispatch.

Después de la aprobación, el job descarga su candidato, verifica otra vez
los bytes, el Worker y ambos SHA. Antes de cualquier write consulta Cloudflare
y requiere:

1. DNS y Pages custom domain canónicos existentes, `fail_open=false`,
   sin proyecto ajeno y con previews sin secretos.
2. **Una única** variable productiva `secret_text`:
   `SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL`, provisionada
   previamente por `bridgesquad_production_proof_bind.py` con Identity
   productivo realmente operativo.
3. Public Identity `id.shadowops.dpdns.org`: JWKS Ed25519, login de
   Bridge Squad y `/readyz` disponibles. No sirve staging.
4. Visitante sin sesión: shell HTTP 401 y acceso a todos los assets denegado;
   `*.pages.dev` GET/HEAD/POST rechazados 404 por el Worker.
5. SHA del deployment actual igual al `expected_live_sha` suministrado,
   distinto del `target_sha`, y `canonical_deployment.id` definido.
   Una modificación concurrente, secreto inesperado, IdP caído o SHA
   avanzado aborta **antes** de subir nada.

Solo entonces se invoca Wrangler fijado por versión para hacer un Direct
Upload de **exactamente tres archivos** al proyecto ya existente, rama
`main`, con el SHA del juego fijado. No crea proyectos, DNS, túneles,
usuarios ni secrets.

El postflight comprueba que el ID del deployment cambió, que el SHA canónico
es el solicitado, que el único secreto sigue cifrado solo en producción y
que raíz/JS/alias siguen denegados a invitados; ante propagación tardía
reintenta de forma acotada. **Si falla el upload o postflight, se declara
estado desconocido/bloqueado, nunca éxito ni rollback automático inventado**.
El Worker de Infra ya sellado y probado debe seguir siendo fail-closed.
Antes de otro intento, un operador debe inspeccionar el deployment y
usar el SHA **real** encontrado, nunca repetir a ciegas.

## Puerta de aceptación que sigue siendo manual

**Un postflight verde NO significa una aplicación abierta y funcional.**
La comprobación productiva pendiente de #611 exige login real en el
hostname definitivo desde escritorio y móvil, cookie host-only,
`aud=bridgesquad`, JWT productivo, lectura de juego autorizada,
renovación, logout/revocación, cambio de cuenta sin heredar progreso,
IdP caído con acceso denegado, y estado final de los aliases
`*.pages.dev` de Cloudflare con HTTP 404. Guardar recibos de SHA,
deployment ID y navegación real antes de anunciar Bridge Squad como
jugable.

Si Identity de producción aún no está arrancado o su proof no está ligado,
el workflow **no puede publicar**: las comprobaciones fallan antes de
Wrangler. El procedimiento de origen/túnel continúa en
`docs/identity-production-origin-operator.md`,
`docs/identity-production-tunnel-operator.md`, y el binding en
`docs/bridgesquad-production-proof-operator.md`.
