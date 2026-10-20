# Chronicles · producción

Producción es igual que staging, con su propio estado. Nada se comparte salvo el host A1 y el wrapper root.

| | staging | production |
|---|---|---|
| Juego | https://staging.chronicles.shadowops.dpdns.org | https://chronicles.shadowops.dpdns.org |
| API | https://chronicles-api-staging.shadowops.dpdns.org | https://chronicles-api.shadowops.dpdns.org |
| Pages project | chronicles-staging | chronicles-production |
| Túnel | chronicles-staging | chronicles-production |
| Compose project / puerto | shadowops-chronicles-staging / 127.0.0.1:18081 | shadowops-chronicles-production / 127.0.0.1:18091 |
| Atlas DB | chronicles_staging | chronicles_production |
| Vault secret | chronicles-staging-runtime-env | chronicles-production-runtime-env |
| GitHub secrets | CHRONICLES_STAGING_* | CHRONICLES_PRODUCTION_* |

## Una sola vez (operador)

1. Atlas: usuario `chronicles_production` con rol propio `readWrite@chronicles_production`.
2. Secrets en `shadowops-infra` (entorno o repo): `CHRONICLES_PRODUCTION_MONGO_URL`,
   `CHRONICLES_PRODUCTION_JWT_SECRET`, `CHRONICLES_PRODUCTION_INVITE_CODE`.
3. Repetir el bootstrap one-shot sin argumentos (`host/bootstrap-chronicles-api-over-ssh.sh`)
   para instalar el wrapper que acepta entorno y el compose de producción.

## Promoción (siempre manual, nunca en push)

1. `Chronicles API` → `provision`, environment `production`.
2. `Chronicles API` → `deploy`, environment `production`, `source_sha` = SHA validado en staging.
3. `Chronicles Pages release` → environment `production`, `source_sha` = el mismo SHA.
   La admisión exige que el SHA esté en `main` protegido; el build falla si apunta a la API de staging.

## Puerta de promoción (control previo a mutaciones)

- Indicar siempre el SHA completo; no se puede usar un `source_sha` vacío en producción.
- Exigir **ambos** recibos verificados y vigentes del mismo SHA: `chronicles-api-staging-<sha>` y `chronicles-pages-staging-<sha>`, de workflows correctos completados con éxito en `shadowops-infra/main`.
- Volver a exigir los tres checks reales de CI de `chronicles-of-matthias` para ese SHA y que el commit pertenezca al historial de `main` protegido.
- Estos recibos prueban generaciones históricas validadas, **no** que staging siga sirviendo hoy ese SHA; consultar el manifiesto público antes de elegir candidato.
- El gate es de solo lectura y se ejecuta antes de cualquier mutación OCI de producción; un recibo ausente, fallido o caducado bloquea el despliegue.
- La promoción real queda bloqueada hasta completar secretos, Atlas, bootstrap del host, Cloudflare y validación de producción; CI verde por sí sola no demuestra un despliegue.
