# Validación criptográfica de materiales MongoDB productivos

**Este procedimiento no genera secretos, no conecta Mongo, no usa Docker
y no toca staging.** Complementa el preflight de metadatos
`identity-prod-mongo-host-inspect`, que solo comprueba owner/modo/CA
legible, con una comprobación real de certificados y clave de réplica.

## Qué verifica

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-verify
```

El segundo comando requiere root y está explícitamente prohibido en
GitHub Actions. Lee únicamente los materiales productivos de ruta fija
`/etc/shadowops/identity-production/mongo`, después de validar su
metadato con `identity_production_mongo_host.inspect_private_files`.
Rechaza cambios en el Compose, claves de firma de CA en ese directorio
y cualquier falta de las condiciones siguientes:

- `ca.pem`: una CA que valide la cadena del certificado de servidor.
- `mongo.pem`: certificado TLS **y clave privada coincidente** en el
  mismo PEM. La validación comprueba la cadena con OpenSSL
  `-purpose sslserver`, el DNS de servicio
  `identity-mongo-production`, `localhost`, la IP
  `127.0.0.1`, y una vigencia restante de al menos **30 días**.
- `replica.key`: un keyFile aleatorio de autenticación interna con
  contenido base64 válido y longitud/variación suficiente (no texto
  corto ni claves inventadas a mano).
- Ningún fichero `ca.key`, `ca-private.key` ni variantes conocidas
  de la **clave privada de firma de la CA** debe estar instalado
  en la A1. Custodiarlo **fuera de la máquina** y nunca subirlo al
  repositorio, backups del servidor ni OCI.

Para comprobar que certificado y clave corresponden se carga
`mongo.pem` en un `SSLContext` **en la memoria del proceso root**;
para revisar `replica.key` se lee también en memoria. No se imprimen
ni pasan valores privados a argv, variables de entorno, red o CI.
Los comandos OpenSSL reciben **solamente rutas fijas** y su stdout y
stderr están descartados deliberadamente; cualquier fallo produce una
línea genérica `IDENTITY_PRODUCTION_MONGO_MATERIAL_REFUSED`.

No ejecutar `mongo-host-start`, `replica-init` ni `admin-create`
si este gate falla. **OK no acredita** que el servidor Mongo esté
arrancado, que exista una cuenta o que funcione un backup/restauración.

## Preparación offline que todavía falta

La CA y clave de réplica deben generarse en una estación de
operación autorizada y el destino productivo recibir **solo**
`ca.pem`, `mongo.pem` y `replica.key`. El instalador/transferencia
es una fase operativa independiente; este cambio no escribe en
`/etc/shadowops` ni crea el directorio en la A1.

La CA debe ser distinta de staging. El archivo PEM y el keyfile
deben quedar a nombre de UID 999, regulares sin enlaces simbólicos,
con modo 0400 o 0600, en un directorio propiedad de root.
La clave privada de CA se conserva en almacenamiento separado
y protegido con recuperación probada.

Referencias: [TLS en MongoDB 7](https://www.mongodb.com/docs/v7.0/tutorial/configure-ssl/)
y [keyfile replica set](https://www.mongodb.com/docs/manual/tutorial/enforce-keyfile-access-control-in-existing-replica-set/).
