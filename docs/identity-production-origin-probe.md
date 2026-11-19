# Identity producción · comprobación HTTPS de origen en localhost

La imagen y el túnel productivos son **candidatos separados**, no desplegados.
Antes de enlazar el túnel con el dominio público, el operador puede ejecutar
un preflight **de solo lectura** desde el mismo host donde se haya
autorizado previamente el arranque de Identity.

Es obligatorio IDENTITY_PRODUCTION_ORIGIN_CA_FILE apuntando al PEM de la
CA del origen productivo, en archivo regular y absoluto, sin symlinks ni
permisos de escritura para grupo/otros. Debe ser la misma CA de confianza
custodiada para cloudflared (IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE),
no la CA de staging.

La conexión sale **solo hacia 127.0.0.1:19443**: nunca resuelve DNS ni usa
un proxy. Aun conectando al loopback, envía SNI id.shadowops.dpdns.org y
verifica el certificado presentado contra ese nombre y la CA indicada,
con TLS >=1.2 y validación de cadena/fecha. Envía siempre peticiones GET
sin cookies ni credenciales, sin seguir redirecciones. Comprueba no-store,
HSTS y nosniff, y rechaza Set-Cookie o Location inesperados.

La prueba reutiliza el contrato estricto de Bridge Squad:
- /livez y /readyz deben devolver 200 (el segundo comprueba Mongo primario).
- /api/identity/jwks debe devolver exactamente una clave pública
  Ed25519/EdDSA canónica, sin material privado.
- /login?app=bridgesquad debe presentar la página correcta con CSP,
  enlaces y retorno fijo al juego.
- /login?app=football debe devolver 400; registro público 503;
  /readyz?unexpected=1 debe ser 405; Host de staging debe ser 403.

Un resultado IDENTITY_PRODUCTION_ORIGIN_OK acredita **solo TLS y superficie
HTTP interna en el momento de esa medición**. No prueba autenticación de un
usuario real, frescura/JWT del Worker, políticas del túnel activo, DNS público,
Cloudflare, ni que el juego sea jugable.

## Uso exclusivo del operador, sin despliegue

Una vez aprovisionados y autorizados Mongo independiente, bundles TLS
productivos, imagen por digest, custodia/rotación y arranque manual del
runtime, ejecutar desde el host que publica loopback 19443:

~~~sh
export IDENTITY_PRODUCTION_ORIGIN_CA_FILE=/ruta/privada/identity-origin-ca.pem
python3 scripts/identity_production_origin_probe.py inspect
~~~

Si falla el certificado, la CA, el host, la disponibilidad de Mongo o
cualquier ruta de seguridad, la comprobación sale con error y no modifica
ni repara automáticamente nada. No imprime respuestas HTTP, material de
claves, credenciales o detalles de TLS/Mongo.

La CI monta únicamente un servidor HTTPS sintético en 127.0.0.1 con CA
y certificado efímeros. Verifica el handshake auténtico, CA incorrecta,
certificado de staging, transporte sin TLS, endpoints degradados, fuga de
cookies, CSP/return URL, JWKS y ausencia de permisos de activación. **CI nunca
se conecta al origen real ni a Cloudflare.**

Queda pendiente el despliegue protegido, un túnel productivo efectivo
y el E2E autenticado en https://bridgesquad.shadowops.dpdns.org/
antes de eliminar la cuarentena HTTP 401. Seguimientos #287 y #611.
