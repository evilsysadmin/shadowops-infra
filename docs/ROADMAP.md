# ShadowOps Infra · Roadmap de plataforma

## P0 — ShadowOps Identity con dos entornos aislados

**Seguimiento: [issue #287](https://github.com/evilsysadmin/shadowops-infra/issues/287)** · estado: diseño y contratos, **sin despliegue de Identity independiente**.

Un único sistema lógico de cuentas por entorno, atendiendo a todos los productos de ese entorno. **No son dos URLs del mismo servidor**: staging y production serán planos de identidad separados, con usuarios, roles de DB, firma, JWKS, sesiones, cookies host-only, backups, políticas y secretos distintos. El mismo username en ambos NO representa la misma identidad. No existe intercambio de tokens ni permisos entre ellos.

| Recurso | Staging (objetivo) | Production (objetivo) |
| --- | --- | --- |
| IdP | `id-staging.shadowops.dpdns.org` | `id.shadowops.dpdns.org` |
| Consumidores | sólo aplicaciones staging | sólo aplicaciones production |
| Datos, secretos, JWT, cookies | exclusivos de staging | exclusivos de production |
| Estado actual | todavía sin desplegar | todavía sin desplegar |

Archivo de contrato machine-readable: [`config/identity/platform-contract.json`](../config/identity/platform-contract.json). Los hostnames de consumidor propuestos NO equivalen a DNS verificado.

### Plan de migración: Strangler Fig + Branch by Abstraction + Expand–Contract

- [x] **P0.0 — Inventario inicial, decisiones y contrato en CI**: mapear SSO de Chess Studio (IdP actual), verificador SSO Chronicles y alcance; definir objetivo por entorno; testear segregación. **No publicar servidores nuevos ni mover cuentas.**
- [ ] **P0.1 — Abstracción y compatibilidad:** congelar contratos públicos de identidad, seleccionar repositorio de servicio independiente y publicar interfaces para ambos entornos. Añadir `sub` estable e inmutable, sin cambiar propietarios de datos existentes. Valorar OIDC Authorization Code + PKCE como evolución protocolaria; no confundir JWT firmado con un servidor OIDC conforme.
- [ ] **P0.2 — Extracción del IdP Go:** crear ShadowOps Identity desde la implementación existente con testes de login/registro, revocación, rotación JWKS, scopes/audiences, migración de usuarios y respaldo. `shadowops-infra` controla exclusivamente infra/deploy/secrets del servicio; no duplicar el código de aplicación en Infra por accidente.
- [ ] **P0.3 — Desplegar sólo Identity staging:** datos, claves, cookies, ingress, TLS, observabilidad, rate-limits, backups y recuperación **propios de staging**. Validar rechazos explícitos de `iss`/JWKS/tokens production, sesiones erróneas y CORS.
- [ ] **P0.4 — Migración progresiva de clientes staging:** Chess Studio, Chronicles; luego CKA staging cuando esté listo. Tokens legacy y nuevos sólo durante ventana limitada y auditable, aceptando únicamente el entorno correcto. Mantener rollback y no hacer doble escritura de contraseñas.
- [ ] **P0.5 — Production aislada:** preparar migración de cuentas después de aceptación staging; backups comprobados, llaves propias, emisión y verificación nuevas, pruebas de revocación y rollback. No copiar la DB staging a prod.
- [ ] **P0.6 — Migración progresiva de consumidores prod:** Chess Studio, Chronicles, CKA. Retirar IdP anterior sólo con tráfico, CI y auditoría de sesión verificados.
- [ ] **P0.7 — AuthN/AuthZ CKA:** audiencia `cka-simulator`, sesiones servidor, roles/quotas/TTL por usuario y aislamiento de runners. La preview pública sigue read-only hasta completar el gate.

### Regla de dependencias

**Bloquea:** AuthN/AuthZ de usuario para laboratorios públicos CKA, y nuevas bases de cuentas por producto.

**No bloquea:** desarrollo offline y CI de kind, banco de escenarios, Ollama en cuarentena, preview estática y mejoras sin exposición de credenciales.

**No autoriza por sí solo:** tocar usuarios actuales, cambiar JWT_SECRET, DNS/Cloudflare/Tunnel, producción, ni asumir que un green CI significa que Identity está desplegado.

### Garantías que deben convertirse en tests

Cada cliente valida exactamente su `iss`, su `aud`, algoritmo, firma/JWKS, `exp` y reloj. Audiencias no reutilizadas para autorización: `chess-studio:admin` NO implica `chronicles:admin` ni derecho a lanzar clusters CKA. Cookie host-only, HttpOnly, Secure, SameSite; orígenes permitidos por entorno; sin wildcard de credenciales; logout y revocación verificables. Las migraciones deben documentar compatibilidad temporal, respaldo y rollback. Las PRs no deben recibir secretos OCI/Cloudflare/Vault.

Referencias: [SSO existente](identity-sso.md) · [arquitectura y cutover](identity-platform.md).
