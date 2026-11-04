# Football — limpieza manual y protegida de runtimes R2

Motivo: el budget privado de Football es **512 MiB** dentro de
`chess-studio-assets`, aunque el bucket compartido admite hasta 7 GB.
Los despliegues Godot inmutables acumulados bajo
`football-of-matthias/staging/releases/<16-hex>/` pueden agotar el límite
propio sin que Cloudflare haya agotado realmente su plan gratuito.

**NUNCA** borrar el bucket, otros prefijos, `football/atlases/`, el bucket
independiente `football` (WebP porteros) o el runtime público/rollback.

## Procedimiento (solo Infra, nunca PR ni automáticamente)

1. Esperar a que termine cualquier despliegue Football pendiente.
   Lanzar [Football · manual R2 obsolete runtime GC](../.github/workflows/football-r2-gc.yml)
   sobre el **main protegido**, acción `plan` y sin `rollback_release`.
   Se imprime el inventario completo de IDs, número de ficheros y bytes sin
   borrar ninguno. Identificar una versión de rollback válida y previamente
   verificada, distinta de la versión pública actual.
2. Volver a lanzar `plan` con `rollback_release=<16 hex>`. El job verifica
   identidad real del `release.json` público, presencia de los cuatro ficheros
   imprescindibles de ambas versiones, bytes del manifiesto activo y el
   inventario R2 completo. Imprime `plan_sha256`, bytes y número de objetos
   candidatos a borrar.
3. Solo cuando el plan sea razonable, lanzar `delete` con **el mismo**
   `rollback_release` y `expected_plan_sha256` copiado literalmente del
   paso 2. El programa vuelve a leer R2 y release público. Ante cualquier
   cambio de SHA activo, objeto, tamaño, forma del prefijo o plan, aborta.
   Las ejecuciones de GC y el publicador Pages comparten lock de Actions.
4. Comprobar `FOOTBALL_R2_GC_VERIFIED` en los logs y volver a ejecutar
   el publicador normal de staging. Este último no pierde los gates de CI,
   ShadowOps ID, WebAssembly, identidad y presupuesto. Verificar el recibo
   `FOOTBALL_STAGING_PUBLIC_VERIFIED` sobre el SHA esperado y el navegador.

**El código no realiza borrados en los runs de PR, push o schedule.** Ni
siquiera una ejecución manual de `plan` borra nada. No existe modo de forzar
el presupuesto ni de saltarse la reserva de un rollback explícito.

El sello SHA-256 representa la instantánea íntegra de inventario + release
público + rollback elegido + objetos a eliminar. No es autorización permanente:
un cambio del inventario hace que deje de ser válido. El job de borrado
revalida el puntero activo entre cada objeto y vuelve a inventariar al final.

**Limitación intencionada:** solo se mantienen explícitamente una versión
pública y una de rollback. Si existen despliegues históricos de Pages a los
que haya que volver, sus runtimes podrían necesitarse más adelante; antes
de aprobar `delete`, verificar cuál es el rollback realmente elegido.
Versiones antiguas no conservadas no son recuperables desde su URL R2 tras GC.

Documentación oficial del endpoint utilizado:
[Cloudflare R2 Delete Object](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/objects/methods/delete/).


## Limpieza automática por presión de capacidad

`scripts/football_r2_auto_gc.py` es un control diferente del borrado
manual de este runbook. Está preparado para integrarse en **el publicador
existente**, bajo su mismo grupo de exclusión, cuando el siguiente runtime
acreditado exceda el límite de 512 MiB (o el presupuesto global de 7 GB).
**No funciona periódicamente, en PR, ni borra nada si el siguiente runtime cabe.**

Antes de cualquier DELETE exige:

- `main` de Infra y `main` exacto admitido de Football, SHA inalterado;
  hashes de artefacto, revisión visual, Godot real, identidad y porteros ya
  comprobados como siempre.
- Identidad de la versión publicada servida mediante `release.json`,
  manifiesto completo y bytes exactos en R2.
- Historia de despliegues de **Pages de Football** (no otros proyectos), con
  `main` y estado `success`. Elige el despliegue previo más reciente cuyo
  `release.json` se pueda leer desde su URL **inmutable y del proyecto
  exacto**, y cuyo SHA y archivos coincidan con los objetos R2 existentes.
  Si Cloudflare responde 404 por un despliegue antiguo, recupera la identidad
  del runtime exclusivamente del artefacto ZIP de **ese mismo SHA**, tras
  verificar el push CI verde con todos sus gates, el digest SHA-256 de GitHub
  Actions, cada archivo del ZIP y el hash del runtime original. Nunca usa
  fechas de objetos R2 para inventarse un rollback.
- Simulación completa: la nueva versión debe caber **después** de la limpieza.
  Límite máximo: 150 objetos / 20 releases obsoletas por operación.
- Inventario intacto y versión pública inalterada antes del primer DELETE,
  revalidación del puntero público durante el proceso y censo final. El
  publicador vuelve a comprobar ambos presupuestos antes del primer PUT.
  Un rechazo deja la versión pública actual sin repuntar.

El mismo lock de GitHub Actions
`shadowops-football-staging-pages` serializa el GC manual y el publicador.

**Activación en dos fases:** el primer PR deja
`FOOTBALL_AUTO_GC: '0'` en el workflow de publicación. El workflow GC en
`main` realiza un `probe` independiente, **solo lectura**, que debe emitir
`FOOTBALL_R2_AUTO_GC_ROLLBACK_PROVEN` con un rollback coherente. Solo
después de comprobar esa evidencia en Cloudflare real, un segundo PR puede
cambiar a `FOOTBALL_AUTO_GC: '1'`. Esta secuencia evita autorizar borrados
en producción de staging basándose exclusivamente en mocks.
