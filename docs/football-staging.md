# Football · staging independiente

Código y CI: `evilsysadmin/football-of-matthias`. Web: https://staging.football.shadowops.dpdns.org/. Pages: `football-staging`, directo desde un artefacto cuyo SHA, hashes de ficheros y ZIP digest fueron acreditados por la CI del repositorio de origen. La puerta obligatoria incluye Godot, revisión visual, carrera y arranque WASM real.

Infra conserva las credenciales; el repo Football no recibe tokens Cloudflare. El frontend y el modo mánager viven en Pages. Los objetos grandes del motor Godot usan el bucket compartido existente `chess-studio-assets`, únicamente bajo `football-of-matthias/staging/releases/<content-id>/`; no se crea VM, bucket, túnel ni capacidad de pago. La URL del bucket es infraestructura compartida, no dependencia del código o CI de Chess. El prefijo se protege frente al GC legado y el publicador rechaza superar 7 GB en el bucket o 512 MiB propios, antes del primer PUT. No tiene bypass de pago ni borra assets ajenos.

Cada frontend fija su runtime por hash; una subida parcial de R2 nunca cambia un frontend activo. Sólo se publica un `main` de Football con CI completa en verde y un artefacto único `football-staging-<sha>`. Una nueva revisión durante la cola invalida la candidata. Los cambios no relacionados de otros productos en Infra no bloquean la entrega si sus scripts/workflow propietarios siguen idénticos.

El workflow se ejecuta al cambiar esta entrega, manualmente o a los minutos 13 y 43. Si el SHA ya está publicado, no despliega otra vez; si la CI de origen sigue pendiente, espera a la siguiente reconciliación. El recibo final es `FOOTBALL_STAGING_PUBLIC_VERIFIED source_sha=<sha>`. Sólo después de verificarlo se corta el host antiguo y se habilita el enlace en el portal. Producción permanece sin publicar.

El staging inicial conserva acceso directo y carreras por navegador. Un dominio no puede leer otro Web Storage: la transferencia de carrera es explícita y valida sólo el journal de Football. Ninguna cuenta/perfil de Chess se copia ni se convierte en autoridad en el cliente.

R2 uses the existing operator R2 credential delivered encrypted as `FOOTBALL_R2_API_TOKEN` in Infra Actions. Pages/DNS retain `CLOUDFLARE_API_TOKEN`; its scope does not include object inventory. No token value is logged or stored in the source repository.
