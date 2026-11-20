# Instalación manual y exclusiva de la PKI de Mongo productivo en la A1

Este procedimiento es **una única instalación nueva**, sin sobrescritura
ni actualización in-place. El código no se ejecuta desde CI, no abre
Cloudflare ni OCI, no inicia Mongo, no instala Identity y **no traslada la
clave firmante privada de la CA**.

## 1. Preparar materiales en L14

Tras la generación local descrita en
[PKI de Mongo producción](identity-production-mongo-pki.md), la única
carpeta transferible es `transfer-THREE-FILES-ONLY`. Conserva
`offline-ca-KEEP-LOCAL/ca-private.key` cifrada y **fuera de la A1**.

En la A1, como `ubuntu`, preparar un único staging dedicado:

```sh
install -d -m 0700 "$HOME/shadowops-mongo-pki-stage"
```

Desde L14, usar el operador **local sin sudo** de transferencia
exclusiva de la carpeta `transfer-THREE-FILES-ONLY`:

```sh
export MONGO_PKI_OUTPUT_DIR="$HOME/shadowops-identity-production-pki-v1"
make identity-prod-mongo-pki-upload-plan
make identity-prod-mongo-pki-upload-check

# Solo tras aprobar la operación de transferencia:
make identity-prod-mongo-pki-upload
# Confirmación: UPLOAD_THREE_PRODUCTION_MONGO_PKI_FILES_ONLY
```

El operador usa `cloudflared access ssh`, el mismo destino canónico
y las claves SSH locales de `make oci-a1-ssh`; admite
`OCI_SSH_KEY` si se necesita una clave explícita. Comprueba TLS/SAN
locales, no permite symlinks/hardlinks ni ficheros adicionales, y lanza
`rsync` con **solo tres rutas exactas** y `--ignore-existing`,
sin `--delete` ni `sudo`. Primero ejecuta una única comprobación
**remota y de solo lectura** por SSH (Python estándar): exige que el
staging ya exista, UID1001, modo 0700, padre privado y contenido
completamente vacío. Si falla, no inicia `rsync`. No crea directorios
ni ejecuta operaciones administrativas remotas.

Un resultado de transferencia **no demuestra** que la A1 tenga ya
material válido. El staging debe quedar exactamente con tres archivos
regulares UID1001/0600 y directorio UID1001/0700; la comprobación
definitiva es el `identity-prod-mongo-pki-host-inspect` en A1.
No adjuntar archivos privados en chats, incidencias o logs.

## 2. Verificar en la A1 (sin instalar)

```sh
# Tras actualizar /opt/shadowops-infra a una release verde:
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-pki-host-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-pki-host-inspect
```

`inspect` valida sin mutaciones:

- A1 `chessbackend`, arquitectura ARM64, root local, fuera de CI,
  cuenta `ubuntu` esperada UID 1001.
- Directorio staging privado UID1001/0700, tres ficheros UID1001/0600,
  sin enlaces, hardlinks, archivos adicionales ni nombres desconocidos.
- Validación criptográfica real de CA, SAN, PEM/clave coincidente,
  vigencia y keyfile Mongo; el staging no debe cambiar durante el
  análisis. Nunca muestra secretos.
- Compose exacto y ausencia de proyecto/volumen/red Mongo productivos
  existentes. La ruta fija
  `/etc/shadowops/identity-production/mongo` **no debe existir**,
  ni como symlink. No se inspecciona, modifica ni adopta staging.

`inspect` no instala nada, no prueba Mongo activo ni configura backups.

## 3. Instalar exactamente una vez (operador humano)

Solo tras aprobar explícitamente el cambio, en la A1, con TTY
interactiva y usuario root:

```sh
sudo make -C /opt/shadowops-infra identity-prod-mongo-pki-host-install
# ACK literal: INSTALL_NEW_PRODUCTION_MONGO_PKI_THREE_FILES_ONLY
```

El operador usa el mismo lock que `mongo-host-start` y
`mongo-replica-init`. Crea si faltan exclusivamente los directorios
de producción con permisos de mínimos privilegios, **sin alterar los
existentes**, e instala solo:

```text
/etc/shadowops/identity-production/mongo/
  ca.pem       (UID/GID 999, 0400)
  mongo.pem    (UID/GID 999, 0400)
  replica.key  (UID/GID 999, 0400)
```

La carpeta Mongo se mantiene inaccesible a otros usuarios hasta
completar la verificación criptográfica sobre los ficheros instalados.
Después queda root:999 con permiso de travesía de grupo, sin permiso
de listado público. No se crea ni copia ningún `ca-private.key`.

**Si falla:** el operador puede dejar un directorio productivo parcial
root-only para investigación. No ejecuta `rm -rf`, ni reintenta,
ni adopta materiales existentes. No repetir `install` hasta
inspección humana y procedimiento explícito de recuperación.
Los contenedores anteriores de Chess Studio, Chronicles y staging
Identity permanecen intactos.

## 4. Después de la instalación

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-inspect
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-verify
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-start-inspect
```

**No ejecutar el arranque Mongo aún** si no están aprobados el
backup externo (cuota, permisos y retención), la restauración de prueba,
el plan de operación y los recursos disponibles de la A1.
La PKI correctamente instalada **no implica** que ya exista un servicio.

Al finalizar, eliminar la carpeta temporal de staging de la A1
mediante el procedimiento interno autorizado, sin tocar la clave
privada de firma conservada en L14.
