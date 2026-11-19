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
