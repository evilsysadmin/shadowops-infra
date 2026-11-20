# Bridge Squad · enlace cifrado de la credencial exclusiva de Identity en Pages

**Estado:** operador preparado en código, NO ejecutado en Cloudflare. DNS y HTTPS
`bridgesquad.shadowops.dpdns.org` existen en modo cuarentena 401. Este
procedimiento NO instala Identity de producción ni publica una versión nueva
del juego. Requiere autorización productiva y los recibos de los operadores
`identity-production-origin.py` y `identity-production-tunnel.py`.

## Prerrequisitos innegociables

- El operador ha desplegado y verificado un IdP **de producción** aislado:
  `https://id.shadowops.dpdns.org` con `/readyz`, JWKS Ed25519 y
  `/login?app=bridgesquad` válidos. NO utilizar
  `id-staging.shadowops.dpdns.org` ni credenciales de Chess Studio.
- Un operador de seguridad ha creado y custodiado en **Vault privado** la
  credencial `soc1_` de 43 caracteres de payload (total 48), registrada
  SOLO para `bridgesquad` en Identity de producción. El script **no**
  genera ni verifica por sí mismo que la credencial esté admitida en el IdP.
- Cloudflare: proyecto único `bridgesquad-production`, rama `main`,
  `fail_open=false` tanto en production como preview, sin variables
  existentes y con el Worker Infra ya instalado. Custom domain y CNAME
  proxied únicos. Aliases `*.pages.dev` deniegan GET/HEAD/POST con el
  Worker 404; raíz, index y assets del dominio canónico deniegan anónimos 401.
- Registrar el **SHA desplegado en Pages**, no adivinarlo a partir del
  `main` del juego. El comando compara SHA antes de escribir y en
  el read-after-write. No actualiza el juego ni mueve ese SHA.
- La credencial Cloudflare usada por el operador debe autorizar solo los
  cambios necesarios en ese proyecto; no usar el entorno Identity staging.

## Comandos (terminal root interactivo autorizado)

Preparar fuera de Git, con un gestor de secretos, un fichero **exactamente
de 48 bytes, sin salto de línea**, propiedad de root, modo `0400` o `0600`.
No poner su valor en argv, variables de entorno, scripts, repositorios,
ficheros de tests ni logs. El nombre del fichero y los tokens Cloudflare
deben custodiarse fuera de Git.

~~~sh
export BRIDGESQUAD_PROOF_FILE=/etc/shadowops/identity-production/bridgesquad-proof
# CLOUDFLARE_ACCOUNT_ID y CLOUDFLARE_API_TOKEN deben cargarse en el
# entorno privado del operador (nunca con valores literales en el historial).

python3 scripts/bridgesquad_production_proof_bind.py plan
python3 scripts/bridgesquad_production_proof_bind.py inspect <SHA_DESPLEGADO_DE_40_HEX>
# Solo tras confirmar a través de los recibos de Identity productivo:
python3 scripts/bridgesquad_production_proof_bind.py bind <SHA_DESPLEGADO_DE_40_HEX>
~~~

`bind` exige UID 0, TTY, ausencia de CI/GitHub Actions y la confirmación
literal `BIND_BRIDGESQUAD_PRODUCTION_PROOF_ONLY`. Antes de abrir el fichero
privado exige host, DNS, aliases, release SHA y superficie pública de Identity
válidos. Realiza **una sola** mutación Cloudflare:

`PATCH /accounts/<account>/pages/projects/bridgesquad-production`, con
`deployment_configs.production.fail_open=false` y exactamente
`SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL` como `secret_text`.

No configura secreto alguno en preview. Tras la escritura relee Cloudflare,
comprueba el tipo cifrado, SHA intacto, fail-closed y denegación HTTP 401/404
de visitantes. Nunca imprime secretos ni el cuerpo devuelto por Cloudflare.
Si el PATCH queda incierto o el postflight falla, el proceso informa
**REFUSED**, sin fingir que se revirtió; un operador debe comprobar/contener
el estado y nunca abrir accesos anónimos como solución.

El watchdog diario existente permite desde ahora solamente dos estados
claramente diferenciados: sin variable (cuarentena) o **una única** variable
`secret_text` de producción (proof-bound-unverified), y en ambos exige
la denegación de todos los aliases y del invitado canónico. El antiguo
operador de alta DNS continúa rechazando cualquier secreto presente.

## Esto NO completa la activación

El enlace del secreto no prueba un usuario, emisión JWT, validez de la
credencial, frescura, revocación ni acceso efectivo a un deployment
existente (Cloudflare puede requerir una nueva publicación para aplicar
bindings). Antes de cerrar [issue #611](https://github.com/evilsysadmin/shadowops-infra/issues/611):

1. Enviar el nuevo bundle exacto del juego, con Worker auditado de Infra y
   SHA verde probado en Chromium, mediante un **release train separado**
   y protección de production (nunca GitHub Pages público).
2. E2E en `https://bridgesquad.shadowops.dpdns.org/`: invitado 401;
   login productivo válido, cookie host-only Secure/HttpOnly,
   `aud=bridgesquad`, `iss` exacto, game 200 tras freshness;
   sesión renovada, logout/revocación inmediata, otro usuario sin
   heredar localStorage y acceso móvil/escritorio a los niveles.
3. Confirmar 404 del Worker para todos los aliases y previews,
   `fail_open=false`, deploy ID/SHA real, restauración 401 ante IdP
   caído, y retirada de una eventual publicación legacy GitHub Pages.

**Nunca declarar el juego jugable por un recibo de este script.**
