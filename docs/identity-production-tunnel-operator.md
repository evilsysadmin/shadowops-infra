# Identity production · segundo paso: túnel, solo operador autorizado

El origen local debe estar desplegado por separado y haber superado su
preflight con Mongo propio, TLS y la clave pública Ed25519 de producción.
Esta herramienta solo organiza el **segundo paso**, sin automatizar DNS,
Pages, Vault ni el acceso al juego.

Archivo: host/identity-production-tunnel.py

- plan: no abre credenciales ni ejecuta Docker.
- inspect: comprueba configuración y recursos de la fase 1, verifica que
  exactamente un Identity productivo está corriendo en localhost, vuelve
  a comprobar TLS/SNI, rutas de salud y ausencia de registro público,
  y verifica que Bridge Squad todavía niega GET/HEAD anónimos con 401.
- start-tunnel: exige root, terminal interactivo y confirmar literalmente
  ENABLE_ONLY_IDENTITY_NAMED_TUNNEL. Usa el **mismo lock de operador**
  del primer arranque para impedir concurrencia. Comprueba que la imagen
  cloudflared con digest fijado existe localmente, sin hacer pull/build.
  Lanza exclusivamente identity-production-tunnel con Docker Compose
  --no-deps, sin reiniciar Identity ni otras aplicaciones.
- stop-tunnel: exige confirmación STOP_ONLY_IDENTITY_NAMED_TUNNEL,
  y detiene únicamente el túnel existente; no detiene Identity ni
  altera Mongo. La parada no requiere que el dominio público funcione.

## Pruebas de aceptación inmediatamente después de start-tunnel

Se repite el chequeo local HTTPS con el certificado del origen validado.
Se obtiene el JWKS público del origen local y se exige una única clave
pública Ed25519/EdDSA de producción sin datos privados. Se consultan
**solo GET públicos** /readyz, /api/identity/jwks y
/login?app=bridgesquad de https://id.shadowops.dpdns.org. La
clave pública expuesta en ese hostname debe coincidir **exactamente**
en todos sus campos con la local; la página login debe seguir apuntando
exclusivamente a Bridge Squad. Esto evita aceptar por error la identidad
de staging u otro túnel aunque devuelvan HTTP 200.

Se vuelve a comprobar la **cuarentena HTTP 401** sobre
https://bridgesquad.shadowops.dpdns.org/ (GET y HEAD) y
/index.html (GET). Si falla el TLS local, el JWKS comparado, la salida
pública o la cuarentena del juego, se intenta detener **solo el túnel
recién creado**. Si la parada falla, el comando devuelve un error
diferenciado que requiere intervención urgente; no afirma rollback.

## Ejecución futura tras autorización operativa explícita

Sobre el **host que ya ejecuta la fase 1**, conservar las mismas
variables privadas que requiere host/identity-production-origin.py.
Los materiales del túnel deben pertenecer a UID 65532 y coincidir
con el preflight estricto. Requiere python3-yaml nativo, Docker Compose
y la imagen cloudflared previamente descargada y verificada por digest.

~~~sh
python3 host/identity-production-tunnel.py plan
python3 host/identity-production-tunnel.py inspect
# Únicamente tras aprobar DNS, secretos, túnel dedicado, rollback y seguridad:
python3 host/identity-production-tunnel.py start-tunnel
# Para desconectar Identity del túnel de forma controlada:
python3 host/identity-production-tunnel.py stop-tunnel
~~~

Esta herramienta **no configura ni confirma la propiedad de un túnel en
Cloudflare**: ese paso debe comprobarlo el operador en su cuenta y con
credenciales de producción separadas. Tampoco autoriza retirar la
cuarentena de Bridge Squad ni afirma que se haya probado un login
autenticado, el Worker, la caducidad, la revocación o los 12 niveles.
Una activación real exige controles independientes de ese tramo.

La CI contiene únicamente dobles de Docker y respuestas públicas sintéticas:
comprueba rechazo de un origen ausente o degradado, túnel preexistente,
JWKS diferente, DNS de Identity caído, acceso anónimo indebido al juego,
errores de arranque y rollback acotado. No inicia túneles, no visita
Cloudflare, no usa secretos reales, no ejecuta un deploy ni modifica DNS.

Seguimiento: ShadowOps Infra #287 y #611.
