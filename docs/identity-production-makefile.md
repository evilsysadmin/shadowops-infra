# Operar ShadowOps Identity production con Make (Bridge Squad)

El DNS/HTTPS `bridgesquad.shadowops.dpdns.org` ya están en Cloudflare
Pages, pero la ruta pública sigue devolviendo 401 hasta que
`id.shadowops.dpdns.org` funcione y se compruebe login real. `make` es
**solo una interfaz legible a los operadores Python existentes**, no
un acceso remoto al host ni una forma de evadir confirmaciones.

Ejecutar desde la raíz de `shadowops-infra`, en el **host productivo
autorizado**, con la versión de `main` auditada. `make help` muestra
los objetivos. No se usa `sudo`, SSH, despliegue automático, GH Pages ni
credenciales de staging por debajo de Make. Los `start`, `apply`,
`create`, `stop` y `bind` siguen requiriendo lo que exige cada
operador (root y/o TTY y confirmaciones literales). Los secretos deben
seguir fuera de Git, de argumentos de comandos y del historial.

## Acceso previo a la A1 desde el L14

El acceso SSH a la A1 existente ya se gestiona desde este repositorio:

```sh
make oci-a1-ssh-check
make oci-a1-ssh
```

Estos comandos se ejecutan **desde tu estación de trabajo** (L14),
usan Cloudflare Access y entran como `ubuntu` en la A1
`chess-studio-staging`; no instalan Identity ni ejecutan automáticamente
ninguno de los operadores productivos. La máquina compartida debe pasar
una revisión explícita de aislamiento antes de admitir servicios de
producción. Consulta [acceso OCI A1](oci-a1-ssh.md).

## 0. Solo lectura: por dónde falla hoy

```sh
make identity-prod-plan
make identity-prod-doctor          # Seguro incluso desde el L14: solo diagnostica ESTA máquina
make bridgesquad-prod-identity-status
make bridgesquad-prod-identity-ready   # Fallará hasta que el IdP REAL esté activo
```

**Importante:** `make identity-prod-doctor` no instala Mongo ni se conecta
por SSH; inspecciona las variables y rutas de **la máquina donde se ejecuta**
sin abrir archivos privados, ni imprimir rutas, SHA, URI, claves o contraseñas.
Por ejemplo, en un ThinkPad sin los materiales productivos indicará
`mongo_admin_uri_file=missing`, `bundle_file=missing` y `root=no`.
Es normal que `make identity-prod-inspect` siga devolviendo
`PRODUCTION_MONGO_REFUSED` hasta preparar el **host productivo**.
No basta con ejecutar `sudo make` en el portátil: el servicio debe operar
en la infraestructura productiva autorizada, no en la máquina local.

`make identity-prod-inspect` ahora imprime primero el diagnóstico
local no sensible y a continuación ejecuta los preflights reales de Mongo
y origen, que mantienen sus denegaciones genéricas para no filtrar URIs,
ficheros de secretos, rutas o errores internos del driver. Un resultado
`present` significa únicamente que existe un archivo regular en esa
máquina, **no** que el secreto, CA, firma, servidor o rol sean correctos.

`identity-prod-plan` no necesita Mongo, Docker, Cloudflare ni secretos
para enseñar las etapas. `identity-prod-inspect` agrupa el chequeo
local de Mongo y origen, **en ese orden**, y se detiene en el primer
fallo; úsalo después de preparar los materiales en el host.

## 0bis. Candidato de Mongo productivo en A1 (sin despliegue)

```sh
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-plan
sudo -n make -C /opt/shadowops-infra identity-prod-mongo-host-inspect
```

Estos objetivos solo describen o inspeccionan la [configuración
independiente](identity-production-mongo-host.md); no arrancan Mongo,
no preparan secretos, no toman backup y no modifican el host.

El [backup cifrado externo](identity-production-mongo-backup.md) tiene
`make identity-prod-mongo-backup-plan` y
`make identity-prod-mongo-backup-inspect`, exclusivamente no mutantes.
La ejecución real solo se autoriza con un servicio/timer root-owned
instalado manualmente y un simulacro de restauración positivo. El
operador de roles/índices de la fase 1 sigue siendo separado.

## 1. Mongo production (recurso real + backup, no fixture CI)

Aprovisionar un replica set con TLS, backup y credenciales de
administración independientes. Preparar la CA y el fichero privado
de URI administrativa, sin copiarlos a Git, y configurar las variables
descritas en [operador Mongo](identity-production-mongo.md).

```sh
make identity-prod-mongo-inspect         # Puede fallar antes del primer alta
# Solo tras revisar clúster/backup, credenciales y autorización:
export IDENTITY_PRODUCTION_MONGO_APPLY=PROVISION_EXACT_PRODUCTION_IDENTITY_DB
make identity-prod-mongo-apply           # Requiere ese ACK explícito + TTY
make identity-prod-mongo-inspect
```

La preparación y el ACK se hacen en terminal privado. El Makefile
**no** establece `IDENTITY_PRODUCTION_MONGO_APPLY` automáticamente.

## 2. Origen Identity en loopback

Verificar y descargar fuera de Make la imagen GHCR por digest, generar
bundle independiente de producción, CA TLS y clave Ed25519 exclusiva
(consultar [origen](identity-production-origin-operator.md) e
[imagen](identity-production-image.md)). Configurar en el entorno del
terminal `IDENTITY_PRODUCTION_IMAGE_DIGEST`,
`IDENTITY_PRODUCTION_SOURCE_SHA`, `IDENTITY_PRODUCTION_BUNDLE_FILE` y
`IDENTITY_PRODUCTION_ORIGIN_CA_FILE`.

```sh
make identity-prod-inspect
make identity-prod-origin-start        # Root + TTY + confirmación explícita
```

`start-origin` solo inicia el servicio Identity en
`127.0.0.1:19443`, nunca el túnel, y prueba TLS/SNI/JWKS; al fallar
intenta detener únicamente ese origen.

## 3. Cuenta productiva aislada y túnel dedicado

```sh
IDENTITY_PRODUCTION_ACCOUNT=bridgeadmin make identity-prod-account-inspect
IDENTITY_PRODUCTION_ACCOUNT=bridgeadmin make identity-prod-account-create
```

El alias de ejemplo es **no secreto**; la contraseña se pide ocultamente
en la consola de producción (nunca se pasa a Make). La cuenta no procede
de staging. La imagen/origen/bundle se revalidan durante su alta.

Preparar por separado los ficheros privados de Cloudflare Tunnel,
`IDENTITY_PRODUCTION_TUNNEL_DIGEST`, configuración y CA de acuerdo con
[operador de túnel](identity-production-tunnel-operator.md). El túnel
debe pertenecer a la cuenta Cloudflare productiva y tener un único
ingress `id.shadowops.dpdns.org`, verificando TLS hasta el origen.

```sh
make identity-prod-tunnel-inspect
make identity-prod-tunnel-start         # Root + TTY + confirmación explícita
make bridgesquad-prod-identity-ready   # Debe verificar JWKS + login reales
```

No se desactiva el 401 del dominio del juego para comprobar el túnel.

## 4. Pages: vincular proof y solicitar release protegido

En el terminal privado del operador Cloudflare, guardar el proof
`soc1_` registrado en Identity en un fichero sin newline con permisos
restrictivos. Configurar `BRIDGESQUAD_PROOF_FILE` y las credenciales
Cloudflare **solo para el proyecto productivo**. Consultar
[operador de binding](bridgesquad-production-proof-operator.md).

El `BRIDGESQUAD_PAGES_SHA` se obtiene de
`bridgesquad-production.canonical_deployment` consultado en la cuenta
Cloudflare; **no se toma de `main` ni de una documentación antigua**.

```sh
make bridgesquad-prod-pages-audit
# Sustituir estos puntos por el SHA real (40 dígitos hexadecimales, sin <>):
export BRIDGESQUAD_PAGES_SHA=... 
make bridgesquad-prod-proof-inspect
make bridgesquad-prod-proof-bind
make bridgesquad-prod-release-plan
```

El último objetivo muestra el contrato, pero **no publica**. El
operador ejecutará manualmente en GitHub Actions el workflow
`bridgesquad-production-release.yml`, con reviewers del environment
`bridgesquad-production`, `target_sha` del `main` verde del juego
y `expected_live_sha` de Pages real. El workflow verifica e instala
`index.html` + Worker auditado, solo en Cloudflare Pages.

Tras la publicación, validar login/cookie/renovación/revocación, cambio
de cuenta y los 12 niveles en escritorio y móvil. Mantener los aliases
`*.pages.dev` en 404 e invitados en 401. No anunciar disponibilidad
por el éxito de un `make` o de CI.

## Parada controlada

```sh
make identity-prod-tunnel-stop
make identity-prod-origin-stop
```

Son comandos separados con sus propias confirmaciones; no hay un
`make down` que tumbe indiscriminadamente bases de datos o túneles.

Seguimiento: [#611](https://github.com/evilsysadmin/shadowops-infra/issues/611).
