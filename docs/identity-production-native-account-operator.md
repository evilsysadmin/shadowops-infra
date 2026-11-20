# Primera cuenta ShadowOps ID productiva — operador de host

Esta herramienta completa el hueco entre `Identity production serve-ready`
ya operativo **en el host privado** y la primera persona que podrá entrar
a Matthias Bridge Squad. No habilita el registro público y no migra cuentas
de Identity staging, Chess Studio ni otros juegos.

Archivo: `host/identity-production-native-account.py`.

## Dependencias de operación y seguridad

1. Un operador ya ha aplicado/auditado el Mongo **de producción** con TLS,
   replica set, índices, backups y RBAC mínimo. Las claves, CA y bundle
   productivo se mantienen exclusivamente bajo custodia privada, fuera de Git.
2. El contenedor `identity-production` fue arrancado con
   `host/identity-production-origin.py start-origin`, usando el digest
   GHCR inmutable y el SHA de Infra que aparece en su etiqueta OCI.
   La herramienta vuelve a validar imagen, Compose, puerto loopback
   `127.0.0.1:19443` y certificado real antes de solicitar una contraseña.
3. El terminal del host es root y **tiene TTY**. El operador debe poseer
   permisos Docker y la ruta privada de CA `IDENTITY_PRODUCTION_ORIGIN_CA_FILE`.
   Necesita también `IDENTITY_PRODUCTION_IMAGE_DIGEST`,
   `IDENTITY_PRODUCTION_SOURCE_SHA` y
   `IDENTITY_PRODUCTION_BUNDLE_FILE` de ese MISMO origen productivo.
   No se requieren archivos del túnel ni credenciales Cloudflare.
4. El nombre nuevo es estrictamente `[a-z][a-z0-9_]{2,31}` y la contraseña,
   **nueva para producción**, tiene al menos 15 caracteres. No utilizar
   contraseñas de staging ni el secreto `soc1_` del consumidor.

## Uso

~~~sh
python3 host/identity-production-native-account.py plan
python3 host/identity-production-native-account.py inspect bridgeadmin

# Terminal root con Identity de producción ya arrancado:
python3 host/identity-production-native-account.py create bridgeadmin
~~~

`create` muestra un reto interactivo:
`PROVISION_ONE_NATIVE_PRODUCTION_ACCOUNT`. Después pide la contraseña
dos veces sin eco. La comprueba localmente, revalida la identidad del
contenedor —incluido su **ID inmutable** por si se recreó durante la
entrada— y la pasa mediante **stdin anónimo** a:

`docker exec -i --user 65532:65532 <ID_VERIFICADO> /app/identity-production provision-native-account <ALIAS>`

**No** usa `-t` (el ejecutable Go exige stdin de tipo pipe), ni argumentos
con contraseña, ni variables de entorno, ni ficheros con contraseña.
No imprime stdout/stderr de Docker porque podrían contener información
privada. El proceso Go utiliza el bundle montado y vuelve a validar
TLS, principal Mongo, replica set, claves y la autoridad antes de escribir
la cuenta. La contraseña se almacena como hash Argon2id, con identificador
UUID independiente de los entornos no productivos.

La creación es de una sola vez: un alias repetido falla sin sobrescribir
contraseñas ni recuperar una cuenta anterior. Si hay timeout o error, NO
repetir creando otros alias hasta inspeccionar el estado de la cuenta
bajo control de un operador; el comando se niega a afirmar éxito.

Este operador no abre rutas HTTP de alta, no reinicia contenedores,
no ejecuta `docker compose up`, no toca Cloudflare/Tunnel/DNS y jamás
corre en CI. Los tests CI usan dobles Docker, contraseñas sintéticas
y certificados ficticios.

## Verificación después de crear la cuenta

El operador debe activar el **túnel público de Identity productivo** con
su procedimiento separado, vincular la prueba `soc1_` únicamente
a la configuración de producción Cloudflare Pages y ejecutar el
release train protegido. Finalmente debe probar en navegador real
`https://bridgesquad.shadowops.dpdns.org/` → login en
`https://id.shadowops.dpdns.org/login?app=bridgesquad` →
retorno al juego, cookie segura y autorización del Worker, renovación,
logout/revocación, aislamiento de progreso por usuario y denegación
de visitantes y aliases.

**Un recibo de alta no prueba que el juego esté accesible.** Mantener
#287 y #611 abiertos hasta los recibos de despliegue y E2E en producción.
