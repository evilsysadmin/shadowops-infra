# PKI de Mongo producción: generación local y transferencia separada

**En esta fase solo se generan materiales en el portátil del operador
(L14), nunca en GitHub ni en OCI.** La herramienta no usa SSH, Docker,
Mongo ni conectividad de red, no ejecuta `sudo`, no instala nada
en la A1 y se niega a ejecutarse en CI o como root.

## 1. En la estación de trabajo, en el checkout local de Infra

Requiere Python 3 y el paquete **nativo** `openssl` instalado mediante
la distribución (sin Snap/Flatpak).

```sh
make identity-prod-mongo-pki-plan
export MONGO_PKI_OUTPUT_DIR="$HOME/shadowops-identity-production-pki-v1"
make identity-prod-mongo-pki-generate
# Escribir exactamente la confirmación que solicita el programa
```

El directorio seleccionado **no debe existir previamente**. El
programa exige un directorio padre dentro del HOME, de propiedad del
usuario y sin escritura por grupo/otros. Crea el destino con 0700
y ficheros 0600, bajo umask 077; no sobrescribe certificados previos.
En caso de fallo conserva la carpeta privada para revisión, no hace
borrados automáticos.

Genera dos subdirectorios privados:

```text
shadowops-identity-production-pki-v1/
  offline-ca-KEEP-LOCAL/
    ca-private.key             # ¡NO transferir a la A1!
  transfer-THREE-FILES-ONLY/
    ca.pem                     # CA pública exclusiva de producción
    mongo.pem                  # certificado de servidor + su clave privada
    replica.key                # clave aleatoria para Mongo replica set
```

- CA ECDSA P-256 independiente, vigencia 1.825 días. Conservar y
  respaldar **cifrada fuera de A1** su clave privada para renovación.
- Certificado de servidor P-256 firmado por dicha CA, 365 días,
  `serverAuth`, SAN exactos
  `identity-mongo-production`, `localhost` y `127.0.0.1`.
- Keyfile Mongo de 384 bytes aleatorios codificados en base64.
- Verificación de SAN, CA y pareja certificado/clave mediante OpenSSL
  **antes** de mostrar el resultado. Los intermedios temporales
  de firma del servidor se eliminan tras comprobar el PEM combinado.

La CA privada queda en `offline-ca-KEEP-LOCAL` sin mezclarse con
`transfer-THREE-FILES-ONLY`. No subir ninguno de los ficheros
privados a GitHub, un chat, una incidencia, un servicio público ni
la Library de artefactos. Proteger el portátil y almacenar una copia
**cifrada** de la CA privada fuera de esa máquina.

## 2. Transferencia manual únicamente de los tres archivos

Conectar previamente a la A1 con `make oci-a1-ssh`; la copia desde
L14 necesita el mismo túnel Cloudflare Access. En la **A1**, crear
una carpeta temporal exclusiva de tu usuario con modo 0700, sin
credenciales compartidas con staging. Después, desde **L14**, copiar
**solo** `ca.pem`, `mongo.pem`, `replica.key` de la carpeta
`transfer-THREE-FILES-ONLY` a ese destino utilizando `rsync`/SSH
por Cloudflare Access. No usar `rsync -r` de toda la carpeta madre,
ya que contiene la clave de firma de CA.

En A1, tras revisar la carpeta temporal y asegurarte de que **no**
existe un despliegue/producto previo, instalar los tres ficheros en
`/etc/shadowops/identity-production/mongo`:

```sh
# Ejemplo: solo tras copiar explícitamente los 3 archivos de L14.
# El directorio TEMP debe ser 0700, del operador ubuntu, con esos 3 ficheros.
set -euo pipefail
temp="$HOME/shadowops-mongo-pki-stage"
test -d "$temp" && test ! -L "$temp"
test "$(stat -c %a "$temp")" = 700
test "$(find "$temp" -mindepth 1 -maxdepth 1 | wc -l)" -eq 3
for name in ca.pem mongo.pem replica.key; do
    test -f "$temp/$name" && test ! -L "$temp/$name"
done
# No adoptar ni sobrescribir otro despliegue Mongo.
if sudo -n test -e /etc/shadowops/identity-production/mongo; then
    echo "Directorio Mongo ya existente: operación cancelada" >&2
    exit 1
fi

sudo -n install -d -o root -g root -m 0750 /etc/shadowops/identity-production
sudo -n install -d -o root -g 999 -m 0750 /etc/shadowops/identity-production/mongo

for name in ca.pem mongo.pem replica.key; do
    sudo -n install -o 999 -g 999 -m 0400       "$temp/$name" "/etc/shadowops/identity-production/mongo/$name"
done

sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-inspect
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-verify
```

Estas instrucciones **no se han ejecutado** y son un procedimiento
para el operador autorizado. En una ejecución real debe revisarse que
la carpeta productiva esté vacía y no se haya provisionado ya
algo antes de llamar a `install`. Tras un resultado satisfactorio,
eliminar las copias temporales de A1 conforme a la política de
gestión de secretos. **Nunca instalar `ca-private.key` en A1.**

El verificador criptográfico en la A1 viene de la PR específica
[Mongo material verification](identity-production-mongo-material.md);
solo comprueba TLS/keyFile, no arranca ni valida un replica set, usuarios
o backups. No continuar con `mongo-host-start` si no pasa.

## 3. Recuperación / rotación

La rotación de la CA **no** puede improvisarse sobre los datos vivos
ni sustituir el certificado sin planificar un reinicio: los clientes de
Mongo también deberán confiar en la CA nueva. No borrar una CA anterior
sin probar la transición, y nunca reutilizar la CA de staging.
Este generador sirve exclusivamente para un despliegue productivo
**nuevo y aún sin datos reales**, no para renovación in-place.

Mongo usa [un PEM con certificado y clave correspondiente](https://www.mongodb.com/docs/v7.0/tutorial/configure-ssl/).
El [keyfile de réplica](https://www.mongodb.com/docs/manual/tutorial/enforce-keyfile-access-control-in-existing-replica-set/)
se mantiene privado con permisos restrictivos.
