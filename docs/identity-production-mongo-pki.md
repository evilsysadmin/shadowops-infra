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

## 2. Transferencia manual e instalación protegida

Conectar previamente a la A1 con `make oci-a1-ssh`. La copia
desde L14 utiliza el mismo túnel Cloudflare Access. **Transferir
exclusivamente** `ca.pem`, `mongo.pem` y `replica.key` de
`transfer-THREE-FILES-ONLY`, nunca la clave privada firmante
de la CA ni el directorio padre.

La instalación queda documentada en
[PKI installation: one-time A1 operator](identity-production-mongo-pki-install.md).
El operador verifica propietarios, modos, nombres, certificados,
clave de réplica y ausencia de recursos previos, sin SSH implícito.

```sh
# En A1, tras transferir los tres archivos al staging privado de ubuntu:
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-pki-host-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-pki-host-inspect

# Solo después de autorizar explícitamente el cambio:
sudo make -C /opt/shadowops-infra identity-prod-mongo-pki-host-install

sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-verify
```

Los operadores rechazan sobrescrituras: si la instalación queda a medias,
no reintentar automáticamente ni limpiar con un `rm -rf`. Ninguno
arranca Mongo, crea usuarios o habilita backups. **La A1 no se ha
modificado desde estos PR.**

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
