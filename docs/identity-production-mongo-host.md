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
  La ruta NO se crea automáticamente si falta.
- Perfil `production-mongo`: ningún `docker compose up` rutinario
  del repo levanta este servicio por accidente.

La red debe ser creada/propiedad del Compose de Mongo. Los overlays del
origen productivo la declaran **`external: true`** y la inspección
del operador exige que exista como red `bridge internal` propiedad
del Compose Mongo correcto, con el Mongo productivo conectado y sin
contenedores ajenos. **No arrancar Identity hasta provisionar realmente
Mongo y demostrar backups/restore.**

## Inspección segura en A1

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-inspect
```

El segundo objetivo solo verifica un Compose con contrato exacto y
metadatos de ficheros, sin conexión a Mongo ni apertura de claves secretas.
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
