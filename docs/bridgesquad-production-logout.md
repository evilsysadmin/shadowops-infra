# Cierre de sesión de Bridge Squad · ShadowOps ID de producción

El sitio del juego se sirve **solo desde Cloudflare Pages** en
`https://bridgesquad.shadowops.dpdns.org`. La autoridad de sesión pertenece
exclusivamente a `https://id.shadowops.dpdns.org`; ambos son hosts distintos.

## Flujo concreto

1. Desde el menú o la pausa del juego, pulsar «Cerrar sesión / cambiar de
   cuenta» navega a `https://id.shadowops.dpdns.org/logout?app=bridgesquad`.
   El juego nunca pide contraseñas, maneja el cookie del IdP ni almacena JWTs.
2. El IdP muestra una **confirmación explícita** por HTTPS. `GET /logout`
   no cambia estado: es seguro frente a navegación accidental o CSRF por
   enlaces de terceros; solo se admite el parámetro exacto
   `app=bridgesquad`. No hay redirecciones externas controladas por query.
3. Al confirmar, un script de origen propio
   `/assets/logout-production.js` realiza
   `POST /api/identity/logout`, con JSON `{}`, credenciales de mismo origen,
   política CSP `form-action 'self'` y sin cabeceras bearer. El endpoint
   preexistente invalida la sesión Mongo y sus tokens derivados y retira el
   cookie `__Host-shadowops_sso_production`. Solo un HTTP 204 confirmado
   autoriza `location.replace` al host canónico del juego.
4. De vuelta en Cloudflare Pages, el Worker sigue exigiendo firma Ed25519 y
   **freshness productiva** antes de cada recurso. Un viejo cookie
   `__Host-bridgesquad` queda inservible al revocarse la sesión del IdP,
   aunque físicamente permanezca en el navegador hasta su corta expiración.
   Un nuevo usuario puede entrar con una cuenta distinta, sin heredar el
   progreso local de la cuenta anterior.
5. Si el IdP está caído, se agota el tiempo o devuelve error, la página
   muestra «No se ha confirmado el cierre» y **no afirma que se haya
   revocado la sesión**, ni fuerza una redirección. El usuario puede
   reintentar desde el mismo host del IdP.

## Invariantes

- No aceptar `/logout?next=...`, otro `app`, métodos distintos de GET
  para las páginas estáticas ni JS servido desde un host externo.
- No habilitar `POST /api/identity/logout` con origen de Cloudflare Pages:
  debe seguir siendo same-origin para impedir CSRF. El juego navega al
  IdP para completar la operación.
- No deshabilitar la verificación de freshness del Worker, no hacer
  públicos los recursos del juego, ni crear Pages en GitHub.
- Las pruebas Go ejercitan página/CSP/GET sin efectos y el POST que revoca
  una sesión real del Mongo **sintético de CI**. El smoke Playwright del
  juego comprueba menú, pausa y URL exacta, con Identity interceptado.
- Esto no demuestra que haya un usuario real ni un Identity desplegado.
  La aceptación productiva sigue exigiendo un navegador autenticado en
  Cloudflare Pages y pruebas de logout/re-login + aislamiento de cuenta
  contra la infraestructura de producción.
