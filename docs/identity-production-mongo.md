# Identity production · operador Mongo aislado (sin ejecución desde CI)

`scripts/identity_production_mongo_operator.py` es un paso **manual** previo
a `service-production serve-ready`. A diferencia del servicio de runtime,
el operador dispone temporalmente de permisos de creación de colecciones,
índices, roles y usuario; esas credenciales **no** se entregan al contenedor
ni a GitHub Actions. No se ejecuta automáticamente ni crea recursos en OCI.

El comando sin dependencias `plan` muestra únicamente los nombres públicos
de recursos admitidos. `inspect` conecta de forma **solo lectura** al Mongo
productivo; exige un réplica set concreto, un administrador autenticado en
`admin`, TLS con CA y URI guardada en fichero propio (0400 o 0600, no
enlace simbólico). `inspect` falla si faltan recursos o detecta desvíos.

Tras comprobar manualmente el clúster, backups, autoridad de las credenciales y
coste/durabilidad, `apply` puede crear de forma conservadora las tres
colecciones exactas y sus índices, el rol
`shadowops_identity_production_runtime` y el usuario fijo
`identity_prod_runtime`. El secreto nuevo del usuario se solicita dos veces
en un terminal de confianza mediante entrada oculta. **No** se acepta
contraseña como argumento, variable de entorno ni JSON de CI. Una segunda
ejecución sobre un esquema correcto es idempotente; si encuentra permisos
ampliados, otros roles, índices alterados o colecciones inesperadas,
**se niega a continuar antes de escribir**. No modifica ni borra objetos
existentes. Si una ejecución se interrumpe, `inspect` permite comprobar el
estado parcial antes de reanudar.

El rol coincide con `ValidateProductionPrivileges` en Go:
`find/insert/update/createIndex/listIndexes` sobre
`native_accounts`, `sessions` y `production_application_tokens`;
`remove` solo en `sessions`. No recibe `createCollection`, acceso de
base completa ni roles de administración. Los índices incluyen alias único,
sesiones con digest único, TTL de sesiones, revocación por sujeto y TTL de
tokens. `NewProductionService` vuelve a verificar privilegios exactos
y que exista primario antes de admitir login.

## Procedimiento manual (no ejecutar hasta validar infraestructura real)

En un terminal del operador, dentro de un entorno Python con `pymongo`
nativo, instalar de forma controlada la dependencia `pymongo` de su
distribución. Preparar fuera del repositorio un URI administrativo
**de producción** en fichero privado y una CA de confianza del Mongo
productivo. El URI debe contener ruta `/admin` y opciones exactas
`tls=true&authSource=admin&replicaSet=REPLICA_REAL`. No imprimirlo
ni pasarlo en argumentos, no usar credenciales ni hosts de staging.

```sh
python3 scripts/identity_production_mongo_operator.py plan

# Solo en el host/terminal de operación autorizado:
export IDENTITY_PRODUCTION_MONGO_ADMIN_URI_FILE=/ruta/privada/admin.uri
export IDENTITY_PRODUCTION_MONGO_CA_FILE=/ruta/privada/mongo-ca.pem
export IDENTITY_PRODUCTION_MONGO_REPLICA_SET=REPLICA_REAL
python3 scripts/identity_production_mongo_operator.py inspect

# Una vez comprobados backup, réplica y propiedad del recurso, decisión explícita:
export IDENTITY_PRODUCTION_MONGO_APPLY=PROVISION_EXACT_PRODUCTION_IDENTITY_DB
python3 scripts/identity_production_mongo_operator.py apply
python3 scripts/identity_production_mongo_operator.py inspect
```

La CA es un archivo de confianza: el script no sustituye comprobaciones de
ownership del clúster, permisos y políticas TLS del proveedor. La base
se crea solo al escribir explícitamente; no hay `dropDatabase`, `dropUser`,
rotación implícita ni restauraciones automáticas. El operador debe custodiar
por separado la contraseña del nuevo usuario, preparar la URI runtime con
`authSource=shadowops_identity_production` en el bundle TLS 0600, y
mantener un procedimiento de copia y recuperación independiente.

**Límites:** CI ejercita con dobles la planificación, las escrituras,
la idempotencia y los rechazos; no provisiona Mongo real ni acredita que el
proveedor tenga réplicas, backups o secretos productivos. Continúan
pendientes despliegue real, ingress TLS, Vault/Cloudflare y E2E autenticado
en el host publicado. Bridge Squad sigue en cuarentena 401.
Seguimiento: [#287](https://github.com/evilsysadmin/shadowops-infra/issues/287)
y [#611](https://github.com/evilsysadmin/shadowops-infra/issues/611).

## Integración con MongoDB 7 real de CI: TLS, RBAC y runtime Go

El workflow [production Mongo TLS RBAC integration](../.github/workflows/identity-production-mongo-live.yml)
arranca un contenedor `mongo:7.0` con un **replica set exclusivamente en
127.0.0.1:27029**, CA y certificado TLS efímeros, `keyFile` efímero y
cuentas sintéticas que desaparecen al terminar. No conecta con Atlas,
OCI, Mongo de staging ni Mongo de producción. El fixture comprueba que el
puerto no estaba ya ocupado y que corre explícitamente en GitHub Actions.

Usa la función de aprovisionamiento sobre ese Mongo **desechable**,
no ejecuta `identity_production_mongo_operator.py apply` (que sigue
prohibido desde CI). Verifica:

- Alta real de tres colecciones, cinco índices, rol y usuario separados;
  repetición idempotente y auditoría posterior sin escrituras adicionales.
- Autenticación efectiva con el usuario del runtime y TLS con CA fiable.
  Mongo niega borrar cuentas/tokens, crear o eliminar colecciones, consultar
  cuentas administrativas y leer la base de staging.
- El `NewProductionService` real de Go arranca con el rol exacto,
  transacciona el alta de una cuenta nativa, emite una sesión y la revoca.
- Después se introduce un segundo rol `readWrite` al usuario de prueba;
  tanto la inspección del operador como el **arranque real** del runtime
  deben rechazarlo. No se intenta corregir automáticamente el rol desviado.

Se trata de una **prueba de integración de infraestructura local**, no de
un despliegue, ni una prueba de Vault, recuperación de bases externas o
retirada de la cuarentena HTTP 401 del dominio público. El provisioning real
continúa bajo custodia y decisión explícita de un operador.
