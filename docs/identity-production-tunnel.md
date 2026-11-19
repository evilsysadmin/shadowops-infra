# Identity production · Cloudflare Tunnel con TLS de origen (candidato, sin deploy)

El runtime productivo de [Identity](../compose.identity.production.yaml)
solo publica TLS nativo en **127.0.0.1:19443**. Este overlay añade,
**exclusivamente si un operador selecciona los dos perfiles**, un cliente
cloudflared de túnel *named*, sin puertos de host, imagen fijada por digest,
UID 65532, filesystem de solo lectura, sin capacidades ni privilegios y
restart: no. No contiene ni genera credenciales. Se mantiene aislado de
Identity staging y de su túnel, issuer y base de datos.

El servicio productivo queda en dos redes: identity-origin (**internal**,
compartida con el túnel) e identity-mongo-egress (salida a Mongo productivo
sobre TLS). Cloudflared solo tiene identity-origin e
identity-tunnel-egress; **no puede usar la red de Mongo**. El puerto del
servicio en el host sigue limitado a loopback. Ningún contenedor tiene acceso
al socket Docker, puerto Mongo público ni credenciales de otro entorno.

## Configuración de ruta obligatoria

El operador deberá crear un túnel de Cloudflare **independiente de staging**,
controlar su JSON de credenciales y la vinculación DNS de
id.shadowops.dpdns.org. El fichero privado de configuración local
contendrá únicamente este contrato (sustituir el UUID ficticio por el propio):

\`\`\`yaml
tunnel: 123e4567-e89b-42d3-a456-426614174000
credentials-file: /run/secrets/identity-tunnel-credentials.json
ingress:
  - hostname: id.shadowops.dpdns.org
    service: https://identity-production:9443
    originRequest:
      originServerName: id.shadowops.dpdns.org
      httpHostHeader: id.shadowops.dpdns.org
      caPool: /run/secrets/identity-tunnel-origin-ca.pem
  - service: http_status:404
\`\`\`

Los nombres y ubicaciones **dentro del contenedor** son obligatorios.
caPool debe contener la CA que valida el certificado TLS real del origen
para id.shadowops.dpdns.org. La conexión a Identity debe comprobar el
certificado y el nombre de host: están prohibidos noTLSVerify, rutas HTTP,
wildcards, reglas extra, configuración de otros consumers y fallback
permisivos. El ejemplo usa un UUID ficticio: no concede acceso.

La ruta del fichero YAML, la credencial JSON **real del túnel** y el PEM de
la CA se aportan por tres ficheros absolutos separados, propiedad de UID
65532 y modo 0400/0600, con todas las rutas sin symlinks. Los tres se
montan **solo lectura** sin crear archivos ausentes. El preflight solo
lee la configuración YAML y la CA; **nunca lee la credencial JSON**.
La CI usa rutas inexistentes sintéticas y no instala secretos.

## Control de admisión manual

Una vez obtenido un túnel independiente, previa aprobación de custodia de
secretos, TLS, Mongo, DNS, rollback y disponibilidad real, el operador puede
establecer localmente:

\`\`\`sh
export IDENTITY_PRODUCTION_IMAGE_DIGEST=sha256:<digest-revisado>
export IDENTITY_PRODUCTION_BUNDLE_FILE=/ruta/privada/identity-production.json
export IDENTITY_PRODUCTION_TUNNEL_DIGEST=sha256:<digest-cloudflared-revisado>
export IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE=/ruta/privada/tunnel-config.yml
export IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE=/ruta/privada/tunnel-credentials.json
export IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE=/ruta/privada/origin-ca.pem

python3 scripts/identity_production_compose_preflight.py inspect
python3 scripts/identity_production_tunnel_preflight.py inspect
docker compose -f compose.identity.production.yaml \
  -f compose.identity.production-tunnel.yaml \
  --profile production --profile production-tunnel config --quiet
\`\`\`

El preflight de túnel necesita python3-yaml de los paquetes nativos de
Debian/Ubuntu. Es **solo lectura** y no comprueba la conectividad real;
ejecutar config tampoco arranca servicios. Cualquier up, configuración
de Cloudflare/DNS o vinculación de credenciales del Worker requiere operación
productiva **explícitamente autorizada**, con un SHA y un digest verificados,
prueba de certificado TLS real en origen y comprobaciones readyz, JWKS,
login, logout, frescura y aislamiento de Pages. Los tests actuales no
sustituyen esa prueba de integración en el dominio publicado.

**No activar el juego ni retirar su cuarentena HTTP 401 con esta PR.**
Seguimiento [#287](https://github.com/evilsysadmin/shadowops-infra/issues/287)
y [#611](https://github.com/evilsysadmin/shadowops-infra/issues/611).
