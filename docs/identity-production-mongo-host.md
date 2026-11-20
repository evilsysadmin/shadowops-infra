# MongoDB productivo de ShadowOps Identity · fase host aislada

Esta fase **no despliega nada** en OCI. La A1 compartida `chessbackend`
tiene 5,8 GiB de RAM, ~4 GiB disponibles y ~23 GiB libres en el
diagnóstico del 20-11-2026, pero las medidas cambian y no constituyen
una reserva garantizada. No hay swap y hay otros servicios de producción.

## Contrato de infraestructura

`compose.identity.production-mongo.yaml` define un **único MongoDB 7 para ARM64**:

- Proyecto `shadowops-identity-production-mongo`; **NO** el proyecto
  `shadowops-identity-staging` ni el proyecto del servicio origin.
- Imagen por digest ya utilizada en staging, pero proceso y datos nuevos.
  `--replSet identity-production-rs` (un solo nodo: transacciones,
  **sin alta disponibilidad**); `--keyFile` y `--tlsMode requireTLS`.
- Volumen exclusivo `shadowops-identity-production-mongo-data`; se
  prohíbe adoptar `shadowops-identity-staging-data`.
- Red interna exclusiva `shadowops-identity-production-mongo-egress`,
  sin puertos publicados ni salida a Internet. Alias DNS
  `identity-mongo-production`. Los otros proyectos de Docker no
  se unen automáticamente a la red.
- Límite de 768 MiB y 0,75 CPU, usuario 999, rootfs de solo lectura,
  `cap_drop: ALL`, `no-new-privileges`, sin Docker socket y
  `restart: no`. Cache WiredTiger acotada a 0,25 GiB.
- Certificados/clave de réplica fuera de Git, bajo
  `/etc/shadowops/identity-production/mongo`, montados como solo lectura.
  La ruta NO se crea automáticamente si falta. Para crearlos en el
  L14 sin mover la clave firmante de CA a la A1, usar el
  [generador offline](identity-production-mongo-pki.md) y transferir
  exclusivamente los tres ficheros del subdirectorio `transfer`.
- Perfil `production-mongo`: ningún `docker compose up` rutinario
  del repo levanta este servicio por accidente.

La red debe ser creada/propiedad del Compose de Mongo. Los overlays del
origen productivo la declaran **`external: true`** y la inspección
del operador exige que exista como red `bridge internal` propiedad
del Compose Mongo correcto, con el Mongo productivo conectado y sin
contenedores ajenos. **No arrancar Identity hasta provisionar realmente
Mongo y demostrar backups/restore.**

## Inspección segura y primer arranque en A1

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-inspect
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-material-verify
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-start-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-start-inspect
```

La fase de primer arranque dispone de un operador explícito
`host/identity-production-mongo-start.py`, independiente de las
funciones del origen/túnel. `plan` es offline; `inspect` comprueba
en el host local el digest ARM64 ya descargado, el Compose renderizado,
los metadatos privados de PKI y que **no existan** previamente
contenedores, volumen ni red con los nombres productivos. Si hay
recursos existentes, **rechaza el arranque**: no los adopta ni los
reemplaza. El repositorio no descarga imágenes ni genera credenciales.

**Solo tras aprobar el host, los backups y las rutas privadas**, el
primer arranque se realiza desde terminal root con confirmación
literal `START_EMPTY_ISOLATED_PRODUCTION_MONGO_ONLY`:

```sh
# No ejecutar todavía hasta superar el preflight y autorizar el arranque.
sudo make -C /opt/shadowops-infra identity-prod-mongo-host-start
```

`start` ejecuta exclusivamente `docker compose ... up --detach
--no-build --no-deps --pull never identity-production-mongo`. Después
comprueba nombre, imagen, UID, volumen, única red interna, ausencia de
puertos y proceso vivo. Si falla detiene **solo** ese servicio y
conserva los datos/volúmenes para inspección. **No ejecuta
`rs.initiate()`, no crea usuarios, no conecta Identity y no instala
el timer de backup**. Hasta la inicialización, que el contenedor
esté `running` no implica un primario healthy; debe quedar fuera
del tráfico y sin cuentas reales. El operador no ejecuta `down`,
`prune`, `rm` ni el túnel de producción.

### Inicialización explícita de un único miembro (paso separado)

Cuando el contenedor productivo esté realmente levantado y
se hayan aprobado la PKI y la configuración de backup:

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-replica-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-replica-inspect

# Mutación manual, después de revisar el resultado inspect:
sudo make -C /opt/shadowops-infra identity-prod-mongo-replica-init
# Confirmación literal: INIT_ISOLATED_PRODUCTION_MONGO_REPLICA_ONLY

sudo -n make -C /opt/shadowops-infra identity-prod-mongo-replica-inspect
```

La nueva herramienta `host/identity-production-mongo-replica.py`
inspecciona el **ID inmutable del único contenedor productivo exacto**,
sin aceptar nombres de staging, host SSH alternativo ni red no privada.
Ejecuta `mongosh` **dentro del contenedor**, conectado solo a
`127.0.0.1:27017`, con TLS y CA dedicada, mediante dos programas JS
estáticos (sin credenciales ni argumentos suministrados por usuario).
La única mutación admitida es el primer `rs.initiate` con
`_id: identity-production-rs` y miembro DNS
`identity-mongo-production:27017`. Rechaza reinit sobre réplica
existente, y espera hasta comprobar `isWritablePrimary=true`.

**Si la elección del primario tarda o falla**, no reconfigurar ni
inicializar por segunda vez a ciegas: la operación puede haberse
persistido; inspeccionar estado y logs sin volcarlos a esta conversación.
No existe rollback automático de un replSet iniciado.

### Primer administrador (operación independiente, no ejecutar aún)

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-admin-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-admin-inspect
# SOLO después de verificar PRIMARY, PKI, permisos y backups:
sudo make -C /opt/shadowops-infra identity-prod-mongo-admin-create
# ACK literal: CREATE_FIRST_PRODUCTION_MONGO_ADMIN_ONLY
```

Este tercer operador es distinto de `start` y `replica-init`. Exige
**root, TTY real y ACK literal** antes de contactar a Docker. Revalida
el ID inmutable del contenedor Mongo productivo, TLS/CA, imagen,
red y volumen, y rechaza si el replica set no está en estado
`PRIMARY`.

El comando `docker exec -it` ejecuta un JS **fijo y no interpolado**
sobre `127.0.0.1:27017`. MongoDB presenta dos peticiones de
contraseña **ocultas** mediante `passwordPrompt()`, obliga a que
coincidan y tengan como mínimo 32 caracteres, crea una única cuenta
`identity_prod_admin` en la base `admin`, con mecanismo
`SCRAM-SHA-256` y rol `root` (break-glass, **jamás el runtime**).
La propia sesión se autentica con esa contraseña y comprueba el rol
antes de anunciar éxito. La contraseña **no pasa por Python, argumentos
de procesos, variables de entorno, CI, ficheros JS ni stdout**.
Recomendación: generarla en tu gestor de contraseñas privado,
guardarla fuera de la A1 y pegarla dos veces durante el procedimiento.
No compartirla en chats, logs ni capturas.

Esta cuenta `root` es para bootstrap y recuperación administrativa;
las cuentas de aplicación y de backup tendrán roles separados de
mínimos privilegios. La `localhost exception` **solo existe antes de
la primera cuenta o rol** y se cierra después de crearla. Ante un fallo
o corte de sesión tras el intento de creación, **no reejecutar create
automáticamente**: la cuenta puede existir ya. Comprobar de forma
manual y autenticada con la contraseña custodiada, sin revelar su valor.
El comando `inspect` informa del estado de la réplica, **no puede
atestiguar la existencia de cuentas sin autenticarse**.

Después debe crearse un fichero URI administrativo de producción
con permisos root 0400/0600, fuera del repositorio, compatible con
`scripts/identity_production_mongo_operator.py`. Esa tarea **no la
hace este bootstrap** y requiere cuidado especial con codificación de
contraseñas de URI. Un primer usuario creado no significa que exista
backup externo ni que Identity pueda arrancar. 

Referencias: [excepción localhost de MongoDB](https://www.mongodb.com/docs/manual/core/localhost-exception/)
y [`passwordPrompt()`](https://www.mongodb.com/docs/manual/reference/method/passwordprompt/).

El segundo objetivo solo verifica un Compose con contrato exacto y
metadatos de ficheros. La [validación criptográfica](identity-production-mongo-material.md)
abre el material privado únicamente en memoria root, verifica cadena TLS,
SAN DNS/IP, clave privada correspondiente y autenticación de réplica sin
imprimir secretos. Ninguno conecta ni arranca Mongo.
Es normal que falle antes de aprovisionar la PKI. Exige directorios de ruta
propiedad de root, no escribibles por grupo/otros, y tres ficheros regulares
propiedad de UID 999 con modo 0400 o 0600:

- `mongo.pem`: certificado TLS + clave privada para el servidor, con SAN
  `identity-mongo-production`, `localhost` y `127.0.0.1`.
- `ca.pem`: CA propia y verificada, independiente de la de staging.
- `replica.key`: clave de autenticación del replica set, aleatoria y
  distinta de staging (no incluir en el bundle de la aplicación).

El directorio raíz puede ser root:999 con 0750 (traversable para UID999);
las rutas padre deben permitir lectura de los certificados al contenedor.
La PKI, permisos, CA y secretos han de ser aprovisionados manualmente
en terminal autorizado o mediante un instalador root-owned revisado.
No colocar contraseñas en argumentos, `environment`, ficheros del
repositorio, shell history ni resultados de CI.

## Gates antes del primer arranque

1. Verificar que la A1 tiene espacio/disco/IO suficiente, no tiene conflicto
   con redes/proyectos existentes y dispone de salida para backups fuera
   de la A1. Reservar cuota y alertas; 768 MiB es un límite, no memoria gratis.
2. Preparar [backup cifrado externo y restore drill](identity-production-mongo-backup.md)
   con OCI Object Storage, retención, alertas y restauración real en
   clúster desechable. El script y timer están listos en Git, **pero
   no están desplegados ni activados**; se requiere prueba real ANTES
   de alojar cuentas.
3. Acreditar que `docker compose -f compose.identity.production-mongo.yaml
   --profile production-mongo config --quiet` muestra únicamente un
   Mongo productivo sin puertos y con volumen correcto. Verificar que la
   imagen pinneada es ARM64 y su procedencia; nada se descarga en CI.
4. Con autorización operativa explícita, arrancar **solo este Compose**
   desde checkout protegido, nunca con `down -v` ni `prune`.
   Inicializar el replica set con un único host DNS
   `identity-mongo-production:27017`. La excepción localhost de
   MongoDB permite crear el **primer** admin; se cierra al crearlo.
   Crear credenciales distintas de staging y guardar URI admin privada
   en fichero 0400/0600; no existe un admin por defecto.
5. Solo entonces validar el operador
   `scripts/identity_production_mongo_operator.py inspect` con PyMongo,
   CA, URI y nombre de réplica **productivos**. El `apply` requiere
   autorización explícita, contraseña oculta y ningún drift de permisos.
6. Verificar conexión TLS desde el contenedor Identity futuro por la red
   compartida controlada. Efectuar prueba de restauración cifrada
   documentada, y posteriormente origen local, túnel y browser E2E
   con invitados permanentemente denegados.

Un replica set de un solo nodo no tolera caída de A1 ni de su disco.
En caso de pérdida, restaurar implica indisponibilidad de login y
posible pérdida de escrituras desde la última copia. No presentar este
diseño como HA ni como continuidad automática.

Documentación MongoDB sobre [excepción localhost y primer usuario](https://www.mongodb.com/docs/manual/core/localhost-exception/)
y [réplica autenticada](https://www.mongodb.com/docs/v7.0/tutorial/deploy-replica-set-with-keyfile-access-control/).
