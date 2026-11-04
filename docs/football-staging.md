# Football · staging independiente

Código y CI: `evilsysadmin/football-of-matthias`. Web: https://staging.football.shadowops.dpdns.org/. Pages: `football-staging`, directo desde un artefacto cuyo SHA, hashes de ficheros y ZIP digest fueron acreditados por la CI del repositorio de origen. La puerta obligatoria incluye Godot, revisión visual, carrera y arranque WASM real.

Infra conserva las credenciales; el repo Football no recibe tokens Cloudflare. El frontend y el modo mánager viven en Pages. Los objetos grandes del motor Godot usan el bucket compartido existente `chess-studio-assets`, únicamente bajo `football-of-matthias/staging/releases/<content-id>/`; no se crea VM, bucket, túnel ni capacidad de pago. La URL del bucket es infraestructura compartida, no dependencia del código o CI de Chess. El prefijo se protege frente al GC legado y el publicador rechaza superar 7 GB en el bucket o 512 MiB propios, antes del primer PUT. No tiene bypass de pago ni borra assets ajenos.

Cada frontend fija su runtime por hash; una subida parcial de R2 nunca cambia un frontend activo. Sólo se publica un `main` de Football con CI completa en verde **en los dos workflows independientes** (visual/Web/manager y `XI · 60s live match and restart recovery`) y un artefacto único `football-staging-<sha>`. El admisor consulta el SHA exacto de `main`, exige ejecución `push` terminada con éxito en ambos workflows y vuelve a comprobarlo justo antes de modificar R2/Pages. Nunca publica con XI pendiente, fallido, cancelado u omitido. El smoke público de ShadowOps ID es posterior a la publicación y su fallo debe tratarse como release no validada, no como preflight. Una nueva revisión durante la cola invalida la candidata. Los cambios no relacionados de otros productos en Infra no bloquean la entrega si sus scripts/workflow propietarios siguen idénticos.

El workflow se ejecuta al cambiar esta entrega, manualmente o a los minutos 13 y 43. Si el SHA ya está publicado, no despliega otra vez; si la CI de origen sigue pendiente, espera a la siguiente reconciliación. El recibo final es `FOOTBALL_STAGING_PUBLIC_VERIFIED source_sha=<sha>`. Sólo después de verificarlo se corta el host antiguo y se habilita el enlace en el portal. Producción permanece sin publicar.

El staging exige ShadowOps ID en el edge y conserva carreras por navegador, separadas por el UUID verificado. Un dominio no puede leer otro Web Storage: la transferencia de carrera es explícita y valida sólo el journal de Football. Ninguna cuenta/perfil de Chess se copia ni se convierte en autoridad en el cliente.

R2 uses the existing operator R2 credential delivered encrypted as `FOOTBALL_R2_API_TOKEN` in Infra Actions. Pages/DNS retain `CLOUDFLARE_API_TOKEN`; its scope does not include object inventory. No token value is logged or stored in the source repository.


El edge conserva `fail_open=false` en producción y previews: una cuota agotada o función no disponible no convierte el sitio en público. El artefacto debe acreditar `authentication={provider:shadowops-id,audience:football,required:true}` e incluir `_worker.js`; una entrega anónima se rechaza antes de mutar recursos.

La activación usa el consumidor admitido por Infra #422. El operador instala el wrapper mediante `make identity-staging-bootstrap`; Actions preserva la custodia, hace backup y despliega la imagen Identity admitida. Un despacho de Football con `force=true` e `identity_binding=activate` copia únicamente su `soc1_` al binding secreto del edge y vuelve a entregar el mismo SHA acreditado. No desactiva hashes, gates ni límites gratuitos. Los despliegues normales preservan el binding.

El smoke público normal prueba denegación anónima y tokens falsos en desktop/móvil. `real_identity_smoke=true` es una comprobación puntual explícita de activación: crea una cuenta ordinaria de staging con credencial aleatoria sólo en memoria, obtiene una sesión nativa y verifica entrada, mánager, WASM de escritorio y revocación/logout. No toca cuentas reales ni concede roles. La cuenta sintética permanece sin sesiones activas; no se crean cuentas en cada reconciliación. Los artefactos excluyen credenciales y cookies. El renderizado del partido en viewport móvil tiene una incidencia visual aparte y no se acredita por el handshake del motor.

The dedicated Pages runtime enables `global_fetch_strictly_public` for its existing public Identity HTTPS hostname (behind the shared zone's Tunnel). This avoids same-zone origin routing for JWKS/freshness without adding another origin, bypassing TLS, or relaxing server authorization. Other compatibility flags and secret bindings are preserved; `fail_open` stays false. See Cloudflare's [public fetch routing contract](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public).

## Atlas WebP canónicos · Publicación manual en R2

Los atlas 3D de Football (carrera lateral, cuatro direcciones y porteros para ambos clubes) se exportan en el repositorio de Football mediante el job `football-r2-atlas-candidates`. Cada ejecución acredita fidelidad RGBA sin pérdida y SHA-256 por hoja. **Generar el ZIP no significa publicarlo**.

El workflow [`football-r2-atlases.yml`](../.github/workflows/football-r2-atlases.yml) no publica nada automáticamente. Su job `contracts` se ejecuta en PR y `main`; el job de escritura requiere `workflow_dispatch`, rama principal, el **SHA completo actual de Football main**, su CI de origen verde y el artefacto con digest acreditado. El operador puede ejecutarlo desde GitHub Actions proporcionando ese SHA. El mismo token `FOOTBALL_R2_API_TOKEN` custodiado en Infra se usa solo dentro del entorno `staging`. Ni secretos ni permisos de R2 llegan a Football o al navegador.

Se admiten **exactamente seis WebP** y `atlas-manifest-v1.json`, bajo `football/atlases/v1/` en el bucket compartido `chess-studio-assets`. Antes del primer PUT se verifica integridad, layout (128×144; 8 celdas por fila), procedencia, inventario completo y presupuesto gratuito. Ningún archivo preexistente se sobrescribe: en reintentos se compara su SHA-256 público. Después se exige que cada WebP público coincida byte a byte con la fuente y que permita CORS para `https://staging.football.shadowops.dpdns.org` y `Cache-Control: immutable`; si faltan estas garantías, **no se declara publicación correcta** y debe investigarse la configuración CDN sin cambiar versiones publicadas. El publicador no actualiza el runtime ni los punteros de Pages.

Tras la publicación acreditada, un PR **por familia** podrá conectar las hojas usando el cargador opcional `ChessFootballR2AtlasLoader` (hash + dimensiones + fallback local). Nunca retirar el canon local ni la compatibilidad offline solo porque exista la URL pública.


## Recepción de porteros: R2 independiente (staging)

Los **dos** atlas WebP de recepción de porteros activados en Football #30 son
distintos de los seis atlas históricos del publicador manual anterior. El
operador los sirve desde el bucket independiente `football`, claves
`atlases/v1/fc_matthias_keeper_catch_v1.webp` y
`atlases/v1/real_enroque_keeper_catch_v1.webp`, a través de
`https://pub-cda6a24cd2f94f7eaaf4d112351bf526.r2.dev/atlases/v1/`.
**No moverlos** al bucket compartido `chess-studio-assets`. Ese bucket
continúa publicando exclusivamente el runtime grande e histórico.

Antes de cualquier mutación de Pages o R2 compartido, Infra lee el manifiesto
opcional `games/chess-football-godot/optional_keeper_catch_v1.json` desde el
**SHA de Football admitido**, nunca desde un HEAD mutable. Si está activado,
`scripts/football_keeper_public.py` verifica desde la URL exacta del
operador ambas respuestas (HTTP 200, no redirect, WebP, tamaño ≤4 MiB,
SHA-256 fijado por el manifiesto, CORS para
`https://staging.football.shadowops.dpdns.org`). El fallo impide publicar una
versión del partido cuyos sprites no podrían obtenerse desde staging. La
comprobación no necesita ni registra credenciales de Cloudflare y nunca
escribe en el bucket `football`.

La URL `r2.dev` es **temporal para staging** y tiene límites de uso.
Cuando se configure el dominio personalizado propio, actualizar juntos el
manifiesto versionado de Football y la raíz permitida por el contrato
de Infra en una iteración verificada. No reducir los controles CORS ni
permitir hosts arbitrarios para sustituir el origen.
