# AGENTS.md — ShadowOps Infra

Este repositorio es la fuente de verdad de la infraestructura compartida de ShadowOps (`evilsysadmin/shadowops-infra`). Los contratos de despliegue y seguridad existentes en workflows, código y documentación siguen siendo obligatorios.

## Cuenta GitHub para ShadowOps

- **Obligatorio:** para leer, escribir, consultar checks, abrir/fusionar PR y operar workflows de `evilsysadmin/*`, seleccionar explícitamente la conexión GitHub **ShadowOps** (perfil `evilsysadmin`). Cuando el esquema de la herramienta exponga `link_id`, pasar el **identificador vigente** correspondiente a `link_name: ShadowOps` en esta sesión. No confiar en una elección por defecto si hay varias cuentas.
- La conexión **Nullforge** (perfil `nullforgeops`) es independiente y no debe utilizarse para estos repositorios ni como fallback. Ante un fallo, verificar la selección explícita de ShadowOps antes de declarar GitHub desconectado o pedir reconexión.
- Comprobar propietario, repositorio, SHA de `main` y estado real de CI/PR antes de escribir o afirmar que un despliegue está activo. No guardar `link_id`, tokens ni credenciales en el repositorio: los identificadores de conexión pueden cambiar.

## Entrega y seguridad

- Mantener cambios pequeños, con PR y comprobación de CI real. No equiparar CI verde con publicación, despliegue o disponibilidad de un servicio.
- Las operaciones sobre OCI, Cloudflare, DNS, Identity y entornos protegidos deben respetar sus workflows y autorizaciones explícitas; no usar secretos de otra cuenta ni puentear controles por comodidad.
- Leer antes de modificar los contratos pertinentes (`docs/`, `scripts/`, `host/`, `.github/workflows/`). No inventar estado de staging ni usar `git push` directamente sobre `main` para evitar revisión.
