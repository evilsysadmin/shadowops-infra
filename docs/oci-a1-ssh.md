# Acceso de operador a la A1 existente desde ShadowOps Infra

**El punto de entrada canónico para operaciones de infraestructura es ahora
`shadowops-infra`**. Los objetivos `oci-a1-ssh` y `oci-a1-ssh-check`
recuperan las funciones SSH originales de
`chess-studio/scripts/oci_a1.py`, sin necesitar un checkout de Chess Studio.

Desde tu L14, en la raíz del repositorio:

```sh
make oci-a1-ssh-check
make oci-a1-ssh
# Si la clave SSH está en una ruta no estándar:
make oci-a1-ssh OCI_SSH_KEY=~/.ssh/mi_clave_a1
```

La herramienta utiliza exclusivamente el hostname existente
`ssh-chess-studio-staging.shadowops.dpdns.org`, con usuario `ubuntu`,
y la opción `ProxyCommand=cloudflared access ssh --hostname %h`.
Mantiene la comprobación previa del DNS y certificado TLS Cloudflare
(port 443), la verificación del host SSH (`StrictHostKeyChecking=ask`) y
el descubrimiento de las claves mediante OpenSSH cuando no se especifica
`OCI_SSH_KEY`. Una clave explícita debe ser un fichero local regular,
sin symlinks y con permisos restrictivos. **La clave privada no se sube ni
se envía a GitHub/OCI**. El acceso interactivo requiere un terminal real y
no se ejecuta desde CI.

`make oci-a1-ssh-check` solo acredita DNS/TLS y herramientas locales:
**no prueba** autenticación de usuario ni Docker/Identity en A1. En caso
de error hay que revisar la configuración de Cloudflare Access, la clave
SSH autorizada, la ruta de cloudflared o el fichero `known_hosts`;
nunca habilitar TCP/22 público como atajo.

## Límites de responsabilidad

Este host de acceso pertenece a la instancia A1 adoptada
`chess-studio-staging`. Compartir la máquina física con posibles
servicios de producción **no autoriza mezclar secretos, Mongo, claves,
issuer, túneles ni datos de staging y producción**.

Los operadores `make identity-prod-*` continúan siendo **locales al
host en el que se ejecutan**. Una conexión SSH abre una shell
`ubuntu`, no concede automáticamente root, materiales privados,
capacidad de despliegue ni una instalación productiva de Identity.
Antes de aprobar el primer servicio de producción deben revisarse
recursos, aislamiento Docker, directorios root-owned, certificados,
Mongo privado, backups, Vault, permisos y la secuencia de rollback.
Consultar [Identity production desde Make](identity-production-makefile.md).

Esta migración NO toca DNS, configuración de Cloudflare, instancias OCI,
puerto 22, Docker ni credenciales de Identity. No crea una ruta de SSH
desde GitHub Actions. El helper de Chess Studio permanece intacto
hasta que se decida retirarlo en otra iteración.
