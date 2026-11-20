# ShadowOps Identity · arranque productivo del origen, fase 1 (manual)

El repositorio contiene la imagen Identity por digest, un Mongo de producción
separado, el Compose productivo, el candidato de túnel y el comprobador TLS
de 127.0.0.1:19443. Hasta ahora faltaba un procedimiento único para iniciar
**solo el origen privado** y detenerlo si la verificación TLS falla.

El operador host/identity-production-origin.py proporciona plan, inspect,
start-origin y stop-origin. **No gestiona el túnel, no instala Mongo, no cambia
DNS, no consume credenciales Cloudflare y nunca se ejecuta desde CI.**
Es una herramienta para un operador con control del host, no una aprobación
para desplegar ni para retirar la cuarentena del juego.

## Secuencia de operación autorizada

1. Aprovisionar previamente un Mongo productivo propio, con backups y rol
   mínimo auditado, credenciales en custodia privada y certificado TLS correcto.
   La [red de Mongo productivo](identity-production-mongo-host.md) debe
   existir **antes** de arrancar Identity; los overlays del origen y túnel
   reutilizan esa red con `external: true`. La admisión inspecciona la
   red Docker: puente interno, etiquetas del proyecto Mongo y ausencia
   de conexiones de staging o contenedores ajenos.
   Revisar la atestación del candidato GHCR del SHA seleccionado, descargar el
   digest inmutable por una vía administrada y verificarlo.
2. Preparar fuera de Git el bundle privado de Identity y la CA TLS del
   origen. Identity debe leer el bundle como UID 65532. **Fase 1 no requiere
   ningún fichero, digest ni credencial de Cloudflare Tunnel.** El operador
   del túnel validará su configuración y la CA compartida de forma estricta
   en la fase 2, sin mezclar staging ni producción.
3. En el **terminal root del host productivo** (rutas ficticias, no incluir
   contraseñas en comandos, CI ni logs):

~~~sh
export IDENTITY_PRODUCTION_IMAGE_DIGEST=sha256:<digest-inmutable-verificado>
export IDENTITY_PRODUCTION_SOURCE_SHA=<40hex-del-commit-admitido>
export IDENTITY_PRODUCTION_BUNDLE_FILE=/etc/shadowops/identity-production/service.json
export IDENTITY_PRODUCTION_ORIGIN_CA_FILE=/etc/shadowops/identity-production/origin-ca.pem

python3 host/identity-production-origin.py plan
python3 host/identity-production-origin.py inspect
# Solo después de aprobar el arranque productivo:
python3 host/identity-production-origin.py start-origin
~~~

plan no abre secretos ni ejecuta Docker. inspect valida exclusivamente el
bundle privado de Identity, su CA TLS y el **Compose de origen-only**; no
necesita ni lee credenciales, imagen o configuración del túnel. Confirma
puerto **solo loopback**, imagen local fijada por digest, etiqueta de fuente
exacta y redes de origen privado / Mongo separadas. El render de ambas fases
se prueba en CI para evitar recreaciones o cambios de red en el corte.
No arranca contenedores ni toca OCI.

start-origin requiere root, TTY interactivo y escribir literalmente
START_LOOPBACK_PRODUCTION_IDENTITY_ONLY. Rechaza CI/GitHub Actions, otro
operador simultáneo, cualquier contenedor del proyecto ya presente o
puerto 19443 ocupado. Invoca únicamente la operación Docker Compose
up --detach --no-deps --no-build --pull never identity-production.
El túnel no se inicia; no hay pull ni build implícitos. Exige después
una sonda de TLS/SNI, JWKS, login, rutas denegadas y /readyz sobre
loopback: si falla, detiene **solo** el servicio origin. Las redes
creadas pueden permanecer y requerir limpieza manual inspeccionada;
no se borran datos Mongo ni volúmenes ajenos.

Para parada deliberada, con el túnel **ya detenido** por procedimiento
separado:

~~~sh
python3 host/identity-production-origin.py stop-origin
~~~

Requiere escribir STOP_LOOPBACK_PRODUCTION_IDENTITY_ONLY. Se niega a
parar si detecta el túnel funcionando, para evitar romper una sesión
productiva estable sin coordinar el corte. No existe docker compose down,
borrado de volúmenes, rotación de secretos ni modificación del resto del host.

## Límites de la CI y activación pública

La CI valida el operador mediante un **doble de Docker**, incluidos
rechazo de comandos ajenos, SHA de imagen incorrecto, puerto ocupado,
túnel inesperado y rollback acotado. También renderiza Docker Compose
real con nombres/rutas sintéticas; **no llama a up**.
No accede a Mongo, Vault, OCI, certificados o cuentas reales.

**Un origen 200 saludable no significa Bridge Squad jugable**:
falta activar el túnel mediante autorización separada, configurar
DNS/credenciales Cloudflare de producción, probar login/JWKS/frescura
y revocación desde un navegador autenticado contra el Worker y completar
los 12 niveles. Hasta entonces HTTP 401 se mantiene en el juego.
Seguimiento: #287 y #611.

## Transición a fase 2 (materiales independientes del túnel)

Cuando el origen haya superado su comprobación TLS/SNI/JWKS en localhost,
preparar las credenciales y YAML de Cloudflare Tunnel, su digest cloudflared
y la CA origin que coincida con la usada por el probe. **Solo entonces**
se establecen IDENTITY_PRODUCTION_TUNNEL_DIGEST,
IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE,
IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE y
IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE para ejecutar
host/identity-production-tunnel.py inspect/start-tunnel.
El script de la fase 2 sigue usando su comprobación completa de ambos
servicios y no inicia automáticamente el túnel. Las redes con nombres
estables son idénticas en los dos Compose para conservar el origen activo.
La parada del origen examina todos los contenedores etiquetados con el
proyecto Docker, incluidos los del túnel que puedan quedar como orphans;
no permitirá una parada si detecta el túnel funcionando.
