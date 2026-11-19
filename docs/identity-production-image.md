# ShadowOps Identity · candidato de contenedor para Bridge Squad

El Dockerfile independiente `services/identity/Dockerfile.production` compila
**exclusivamente** `cmd/service-production` para Linux AMD64/ARM64. No modifica
el contenedor del emisor de staging y no lleva ningún certificado de servicio,
JWT key, credencial de Mongo ni prueba privada del consumidor en la imagen.

La CI `identity-production-image.yml` valida el runtime Go, construye una
imagen AMD64 y demuestra que **no arranca sin un modo explícito** y que
`serve-ready` falla si no se proporciona el bundle privado. Tras un push
con tests verdes del SHA actual de Infra `main`, publica un candidato de
dos arquitecturas en GHCR bajo:

`ghcr.io/evilsysadmin/shadowops-identity-production-candidate:sha-<SHA>`

Sin etiqueta `latest`. El workflow registra el digest y adjunta una
atestación de procedencia. **Publicar la imagen no despliega el Identity
productivo ni autoriza levantar la cuarentena de Bridge Squad**.

El contenedor final es `scratch`, funciona como UID/GID 65532 y recibe
solo una ruta de *bundle* predeterminada:
`/run/secrets/identity-production.json`. El operador futuro debe montar
en esa ruta un fichero individual de configuración productiva con permisos
0600, propietario que pueda leerlo desde el UID 65532, y claves separadas
del staging. La imagen **no** incluye `CMD`: ejecutar la imagen sin
argumentos falla; pasar `serve-ready` es una elección manual explícita,
que a su vez exige verificar TLS, base de datos de producción y rol Mongo
limitado a las tres colecciones permitidas. Nunca pasar contraseñas como
argumentos de Docker ni copiar el bundle a un build context.

Antes de cualquier runtime productivo aún son necesarios el aprovisionamiento
real de Mongo, TLS, roles y secretos custodiados; el ingress restringido y
con pruebas de TLS; un plan de alta/recuperación y copias; vincular el secreto
separado a la configuración **protegida** de Cloudflare; una prueba de navegador
con login auténtico y revocación, y la comprobación de que los alias Pages
siguen sin exponer activos. El DNS de Bridge Squad sigue en cuarentena
`HTTP 401` hasta que todos esos requisitos se acrediten.

Seguimiento: [#287](https://github.com/evilsysadmin/shadowops-infra/issues/287)
y [#611](https://github.com/evilsysadmin/shadowops-infra/issues/611).

## Definición Compose de producción: manual y cerrada por defecto

`compose.identity.production.yaml` prepara la **ejecución futura** del
candidato de Identity sin desplegarlo ni tocar OCI. La imagen debe declararse
por digest `sha256:<64 hex>` mediante `IDENTITY_PRODUCTION_IMAGE_DIGEST`;
nunca usa la etiqueta `latest` ni una imagen compilada en el host. El
servicio tiene el perfil explícito `production`, `command: serve-ready`,
UID 65532, filesystem de solo lectura, sin capacidades, sin privilegios
adicionales, memoria y procesos acotados y `restart: no`. No modifica los
servicios Docker/Compose de staging.

El puerto **no es público**: `127.0.0.1:19443 -> 9443`. Este contenedor no
configura Cloudflare, TLS ingress, DNS ni firewall. Antes de habilitar el
hostname público se necesita un proxy separado revisado, que conserve SNI,
host canónico `id.shadowops.dpdns.org` y TLS extremo a extremo, además de
evidencia real de aislamiento de recursos y de los endpoints.

Solo se monta un fichero de bundle privado, en
`/run/secrets/identity-production.json:ro`, con
`bind.create_host_path=false`: no se crea un fichero/directorio inexistente
por accidente. El operador debe preparar el fichero fuera de Git y con
UID 65532, modo 0400 o 0600, tamaño acotado y sin enlaces simbólicos en la
ruta. La CI nunca lo lee, monta ni genera.

En el **host productivo que vaya a ejecutar Docker**, antes de cualquier
`up`, proporcionar manualmente las variables de entorno con la referencia
del digest previamente verificado en GHCR y con la ruta absoluta del bundle:

```sh
python3 scripts/identity_production_compose_preflight.py inspect
docker compose -f compose.identity.production.yaml --profile production config --quiet
# Arranque EXCLUSIVAMENTE tras autorizar Mongo+TLS+Vault+ingress+rollback:
# docker compose -f compose.identity.production.yaml --profile production up -d
```

El preflight es solo local y de **solo lectura**: rechaza digest inválido,
ficheros inexistentes, ruta relativa/symlink, permisos de grupo/otros, propietario
que el contenedor no puede leer, y cambios de contrato en Compose. No lee
el contenido del bundle ni verifica por sí mismo la clave productiva ni la
conectividad con Mongo. `serve-ready` vuelve a comprobar esos requisitos y
falla cerrado ante cualquier error.

La CI verifica con Docker Compose real la configuración renderizada,
los puertos exclusivamente loopback, el digest, los bind mounts y la
ausencia de autoarranque; **no ejecuta `docker compose up`**. No instalar
esta definición en staging ni confundir las pruebas offline con Identity
productivo desplegado. Continuar #287 y #611.
