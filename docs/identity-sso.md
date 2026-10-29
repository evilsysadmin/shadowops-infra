# ShadowOps · cuenta única (SSO)

> **Flujo heredado de Chess IdP.** Este documento describe la integración
> existente Chess Studio → Chronicles. Para el servicio Identity independiente
> y su aceptación de cuenta única, prevalece [identity-platform.md](identity-platform.md).
> El nuevo proveedor usa un `sub` UUID; **no basta con cambiar la URL del emisor**:
> los consumidores deben verificar ese identificador y aplicar un mapeo de datos
> legacy cuya propiedad esté comprobada. Un mismo username no acredita que dos
> cuentas pertenezcan a la misma persona. Las notas históricas de vinculación por
> nombre de este documento no autorizan fusiones automáticas ni nuevos cutovers.
> El cierre de cookie del flujo heredado tampoco prueba revocación inmediata de
> sus JWT: la nueva biblioteca de Identity añade comprobación de vigencia por
> operación, aún pendiente de conectar al transporte y a los productos.


Una sola cuenta para Chess Studio, Chronicles y los juegos que vengan. Te registras una vez; entras una vez y estás dentro en todos.

## Decisión

- **Proveedor de identidad (IdP): la API de Chess Studio** (`pvp-edge`, Go). Ya tiene usuarios, registro con invitación, recuperación por correo (Resend), bloqueo por intentos y admin. Más adelante puede extraerse a `id.shadowops.dpdns.org` sin que los juegos cambien: sólo cambia el emisor.
- **Cada juego verifica, no autentica.** Ningún juego guarda contraseñas ni comparte secretos con el IdP: verifica tokens firmados con clave pública.
- Entornos aislados: Chronicles staging confía en Chess Studio staging; Chronicles prod en Chess Studio prod.

| | staging | producción |
|---|---|---|
| IdP | `https://api-staging.chess-studio.shadowops.dpdns.org` | `https://api.chess-studio.shadowops.dpdns.org` |
| Usuarios | `chess_study_staging.users` | `chess_study.users` |

## Por qué funciona con una cookie

`dpdns.org` está en la Public Suffix List, así que `shadowops.dpdns.org` es un *site* propio y todos los juegos (`*.shadowops.dpdns.org`) son *same-site* entre sí. Una cookie `SameSite=Lax` de la API del IdP viaja en los `fetch(..., {credentials: 'include'})` que hace cualquier juego hacia ella. No hace falta `Domain=`: la cookie es *host-only* del IdP y ningún juego la ve.

## Piezas

### En el IdP (Chess Studio, Go)

1. **Cookie de sesión SSO.** Login y registro, además del token *bearer* de siempre, ponen
   `shadowops_sso=<JWT de sesión>; HttpOnly; Secure; SameSite=Lax; Path=/api/identity; Max-Age=30d`.
   Logout la borra. Chess Studio sigue usando su *bearer* como hoy: nada cambia para él.
2. **`POST /api/identity/token`** `{ "audience": "chronicles" }` con la cookie → `{ token, username, expiresAt }`.
   - Token **EdDSA (Ed25519)**, 1 hora: `{ iss, aud, sub, sv, iat, exp }`.
   - Exige `Origin` en la lista de esa audiencia (CORS con credenciales sólo para esos orígenes) y `Content-Type: application/json` (sin CSRF por formulario).
   - Comprueba el `sv` (versión de sesión) contra el usuario: cambiar contraseña o cerrar todas las sesiones revoca en ≤ 1 h.
3. **`GET /api/identity/jwks`**: la clave pública (JWKS). Pública y cacheable.
4. **CORS con credenciales** en `/api/auth/login`, `register`, `forgot-password`, `reset-password` y `/api/identity/*`, sólo para los orígenes de los juegos.
5. **Clave de firma** derivada del `JWT_SECRET` existente con HKDF (`"shadowops-identity-ed25519-v1"`). Sin secreto nuevo en Vault; rotar el `JWT_SECRET` rota también la clave (el `kid` es la huella de la pública).

### En cada juego (Chronicles primero)

1. **API**: acepta tokens EdDSA con `iss` = su IdP y `aud = chronicles`; descarga y cachea el JWKS del IdP (por defecto según `ENVIRONMENT`, sin cambiar el wrapper). Crea el usuario local la primera vez (sin contraseña) para presencia/admin. Los datos siguen indexados por nombre de usuario.
2. **Front**:
   - Al abrir: canje silencioso de token con la cookie. Si hay sesión, entra directo.
   - Si no: formulario de login/registro que habla **con el IdP** (mismas credenciales que Chess Studio, mismo código de invitación) y después canjea el token.
   - Renovación silenciosa antes de caducar o ante un 401.
   - Fuera: registro, recuperación y cambio de contraseña propios (enlazan al IdP).

## Migración

- Las cuentas de Chess Studio son las canónicas.
- Las de Chronicles staging se enlazan por nombre de usuario: si existe en Chess Studio staging, es la misma persona (revisar la lista a mano antes; hoy es básicamente `evilsysadmin`). Partidas y progresión no se mueven: ya van por nombre de usuario.
- Chronicles producción arranca ya con SSO: nunca tendrá cuentas propias.

## Fases

1. **IdP**: cookie SSO, `/api/identity/token`, JWKS, CORS. Chess Studio sin cambios visibles. *(chess-studio, PR no visual)*
2. **Chronicles API**: verificación EdDSA + JWKS + usuario local JIT; convive con el login propio. *(chronicles-of-matthias)*
3. **Chronicles front**: login vía IdP, canje silencioso y renovación; se retira el registro propio. *(chronicles-of-matthias, PR visual)*
4. **Chronicles producción** con SSO desde el primer día.
5. *(Opcional)* Chess Studio usa también la cookie (entrar en un juego te deja dentro en Chess Studio).

## Riesgos

- **El IdP es punto único**: si la API de Chess Studio cae, nadie entra en ningún juego (quien ya tiene token sigue jugando hasta 1 h).
- **Navegadores que bloquean cookies de terceros**: no aplica (same-site), pero Safari con «bloquear todas las cookies» rompería el canje silencioso → cae al formulario.
- La rotación de `JWT_SECRET` de Chess Studio invalida a la vez sesiones y tokens de juego (aceptable: es lo que se espera de una rotación).
