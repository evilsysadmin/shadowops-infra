# ShadowOps Identity production · backup Mongo cifrado y restore drill

## Estado y política

Código de operador **preparado, no desplegado ni habilitado**. Un
replica set de un solo nodo pierde disponibilidad cuando cae la A1;
el objetivo es RPO aproximado 24 h **solo después** de demostrar
copias diarias válidas. Ni el timer ni CI arrancan Mongo o Identity.

El flujo está diseñado para la A1 `chessbackend`:

`mongodump --oplog --archive --gzip` (100.x, copia completa de
replica set) → tubería de procesos → `age -R` (cifrado local) →
**único fichero cifrado** temporal (0600) → OCI Object Storage
`put --no-overwrite --verify-checksum` → verificación de longitud remota
mediante `object head` → borrar copia local cifrada **solo al confirmar**.

Nunca escribe archivos Mongo en claro en el host ni almacena la
contraseña en argumentos/env/CI. La contraseña de backup reside solo
en un fichero privado dentro del contenedor, UID 999, y se consume por
`mongodump --config`. Este backup incluye las bases administrativas,
cuentas y roles: **los datos restaurados son sensibles**. La clave
privada de descifrado **no se guarda en la A1**.

No usar contenedores, ficheros, usuarios Mongo, claves o backups de
`shadowops-identity-staging`. El código rechaza si el proyecto, volumen,
red, imagen, estado healthy o UID del contenedor no son exactamente
los productivos.

## Preparación fuera de Git

**No ejecutar aún en A1; requiere aprobar el despliegue Mongo de la
fase anterior y verificar el backup.**

1. Crear bucket privado de OCI Object Storage en la cuenta aprobada,
   con cuota libre, política de retención y acceso controlado por
   **instance principal** de la A1 (escribir/leer solo en el bucket
   autorizado). No crear tokens de usuario ni claves API en el host.
   Configurar alarmas por error, cuota, última copia y capacidad.
2. Instalar herramientas nativas: `age`, `oci` (CLI oficial),
   `docker` y MongoDB Database Tools 100.x en la imagen de Mongo.
   No Flatpak/Snap. Verificar que el OCI CLI con
   `--auth instance_principal` accede solo al bucket autorizado.
3. Generar **fuera de la A1** una identidad `age` de recuperación
   (`age-keygen`) y custodiar su clave privada en un dispositivo/offline
   distinto. Instalar SOLO el destinatario público en
   `/etc/shadowops/identity-production/backup-recipients.txt`
   (root, 0400/0600). Probar el descifrado desde otro equipo.
4. Crear un usuario exclusivo de Mongo con rol `backup`, sin permisos
   de escritura. Existe el operador específico de este paso, **separado**
   del primer admin y de la inicialización de la réplica:

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-backup-user-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-backup-user-inspect
# Solo tras aprobar la operación y con admin ya creado:
sudo make -C /opt/shadowops-infra identity-prod-mongo-backup-user-create
# ACK: CREATE_PRODUCTION_MONGO_BACKUP_USER_ONLY
```

   Se conecta con `mongosh --username identity_prod_admin` a
   `127.0.0.1:27017` **dentro del único contenedor productivo**,
   utilizando TLS/CA y una petición enmascarada de la contraseña
   administrativa. Después solicita **dos veces** una contraseña nueva
   de al menos 32 caracteres para `identity_prod_backup`, crea
   exclusivamente el rol integrado `backup` en `admin`, y verifica
   el rol exacto. Nunca imprime secretos, modifica staging ni reintenta
   automáticamente una creación fallida. **Generar y custodiar ambas
   contraseñas fuera de la A1; son cuentas distintas**. El operador
   no habilita el backup ni crea el fichero privado.

   Guardar en
   `/etc/shadowops/identity-production/mongo/backup-tools.yml`
   (UID 999, 0400) un fichero YAML con `uri` y `password`.
   La URI apunta exclusivamente a
   `identity-mongo-production:27017`, con
   `authSource=admin`, `replicaSet=identity-production-rs` y
   `tls=true`. **No especificar una base de datos en la ruta de URI**
   (la copia con `--oplog` ha de ser completa).
   El script jamás lee ni muestra el contenido del YAML.
5. Preparar el directorio
   `/var/lib/shadowops-identity-production/backup-staging`
   con root:root y modo 0700; padres root-owned sin escritura
   de grupo/otros. Mantener al menos 8 GiB libres: si no, se niega
   a ejecutar y alerta. Los artefactos cifrados fallidos se retienen
   allí; vigilar espacio y revisar incidentes, nunca borrarlos a ciegas.
6. Instalar `/etc/shadowops/identity-production/backup.env`
   (root, 0600), con SOLO estos identificadores y el consentimiento
   literal **cuando la operación real esté aprobada**:

```ini
IDENTITY_PRODUCTION_BACKUP_BUCKET=mi_bucket_privado
IDENTITY_PRODUCTION_BACKUP_NAMESPACE=mi_namespace_oci
IDENTITY_PRODUCTION_BACKUP_ENABLE=UPLOAD_ENCRYPTED_PRODUCTION_MONGO_TO_OCI
```

No colocar tokens, passwords, URIs ni rutas con credenciales en ese env.

## Comprobación y automatización (manual)

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-backup-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-backup-inspect
```

El `inspect` no se conecta a Docker ni a OCI: solo valida binarios,
metadatos, CA, directorio local y parámetros públicos de bucket.
Un resultado OK **no demuestra** que exista un backup o permisos en OCI.

Cuando Mongo real esté saludable, el restore drill esté documentado,
las credenciales del principal de instancia estén restringidas, y
el bucket haya sido probado, instalar manualmente
`host/identity-production-mongo-backup.{service,timer}` bajo
`/etc/systemd/system/` por un operador root autorizado; inspeccionar
el contenido y permisos antes de instalarlo. Solo entonces:

```sh
sudo systemctl daemon-reload
sudo systemctl start identity-production-mongo-backup.service
sudo systemctl status identity-production-mongo-backup.service --no-pager
# Tras verificar al menos una copia y el restore drill:
sudo systemctl enable --now identity-production-mongo-backup.timer
sudo systemctl list-timers --all | grep identity-production-mongo-backup
```

El timer opt-in hace una copia diaria a las 04:30 UTC con
`RandomizedDelaySec=10min` y `Persistent=true`. No se instala
ni activa por ninguna PR, push, Makefile ni workflow. El modo
`backup` requiere root y el ACK exacto. Exige un único Mongo real,
healthy, ligado a la red y volumen productivos, y comprueba
checksum de subida y tamaño remoto. No modifica datos ni bases Mongo.

Si falla la copia o el upload, el operador devuelve código no cero;
comprueba `journalctl -u identity-production-mongo-backup.service`
y el área local cifrada privada. **No hay borrado remoto automático**
ni rotación de claves automática; la retención/lifecycle del bucket
debe ser configurada y revisada por separado.

## Simulacro de restauración aislado

**Nunca ejecutar `mongorestore` sobre la A1 productiva en este
procedimiento.** El destino obligatorio es una instancia Mongo
completamente desechable, sin redes de producción, sin datos valiosos
y sin acceso al Docker socket de la A1. Antes de activar el timer:

1. Desde un equipo autorizado **distinto de A1**, descargar
   **un objeto concreto** con
   `oci os object get --bucket-name ... --namespace-name ... --name ...
   --file backup.age`. Verificar hash/tamaño contra recibos.
   Nunca imprimir el ciphertext ni credenciales.
2. Con la clave privada `age` custodiada fuera del host, probar
   descifrado por tubería hacia MongoDB Database Tools, con una
   configuración privada de **destino efímero** para `mongorestore`.
   No usar la URI de producción, ni siquiera como valor por defecto:

```sh
# EJEMPLO SOLO EN UN ENTORNO EFÍMERO; revisar previamente destino y permisos.
age -d -i /ruta/segura/clave-privada.txt backup.age |
  mongorestore --config /ruta/segura/restore-disposable.yml \
    --ssl --sslCAFile /ruta/segura/ca-disposable.pem \
    --archive --gzip --oplogReplay
```

3. Comprobar en la instancia desechable los tres almacenes
   `native_accounts`, `sessions` y
   `production_application_tokens`, sus índices y roles,
   y que ninguna cuenta de staging pueda autenticarse.
   Ejecutar pruebas de login/revocación **solo sintéticas** y sin
   publicar el IdP restaurado. Registrar fecha/objeto/hash,
   RPO/RTO medidos y resultado de la prueba, sin claves ni datos privados.
4. Borrar el clúster efímero y su material sensible solo después de
   registrar la prueba; no utilizar el simulacro para reactivar sesiones
   revocadas ni para restaurar bases productivas automáticamente.

**El backup almacenado no acredita recuperabilidad:** hasta que el
simulacro real termine, la activación de Identity y Bridge Squad
sigue bloqueada.

Referencias: [MongoDB herramientas de backup coherente](https://www.mongodb.com/docs/manual/tutorial/backup-and-restore-tools/),
[`age` cifrado por destinatario](https://github.com/FiloSottile/age),
[OCI Object Storage put](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os/object/put.html).
