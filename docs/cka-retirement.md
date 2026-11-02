# Retirada online de CKA; repositorio conservado

Decisión del propietario: CKA se usa solo en local mediante `make up` en `evilsysadmin/cka-exam-simulator`. No eliminar el repositorio, su historial ni los recursos compartidos de ShadowOps.

Al integrar esta retirada, Actions ejecuta automáticamente `withdraw`: quita DNS y Pages, hace que los orígenes respondan 404, revoca el consumidor CKA en Vault y programa la eliminación de sus secretos dedicados. No necesita esperar al SSH para cerrar el acceso público; los conectores y el runtime se retiran a continuación. Si los conectores ya están detenidos, el mismo workflow elimina también los túneles y emite el recibo final. El recibo parcial es `CKA_RETIRE_PUBLIC_WITHDRAWN`, todavía no el recibo final.

Desde la estación de operador con la misma clave/Cloudflare Access de los bootstraps anteriores:

```sh
git pull --ff-only
make cka-retire-host
make cka-retire-inspect
```

Esto detiene y elimina los contenedores de cuenta y su conector; elimina el daemon rootless exclusivo de labs, el nodo kind, el disco privado de 8 GiB, su usuario, unidades y política instalada. Si se instaló la fábrica CKA, también se retira su unidad, usuario y directorios exclusivos. Quita únicamente `cka-simulator` del fichero de consumidores de Identity, conserva el inode montado y reinicia solo su contenedor para revocar esa autoridad. Comprueba que los otros contenedores mantienen su estado e instante de arranque. No desinstala Docker, paquetes compartidos, redes Identity, bases de datos, SSH, el A1, Vault ni claves.

Después, en GitHub Actions de este repositorio, ejecuta **CKA · retire online resources (keep repository)** sobre `main`, primero `action=plan` si quieres ver el inventario y después `action=retire`. El operador ya ha autorizado la retirada; estos pasos existen porque el root de la A1 solo se opera por SSH y los secretos cloud solo están disponibles en Actions.

Recursos exclusivos autorizados:

| Recurso | Nombres |
| --- | --- |
| Pages, incluidos todos sus despliegues | `cka-simulator`, `cka-account-staging` |
| DNS | `cka.shadowops.dpdns.org`, `staging.cka.shadowops.dpdns.org`, `cka-api-staging.shadowops.dpdns.org`, `cka-labs-staging.shadowops.dpdns.org` |
| Túneles | `cka-account-staging`, `cka-lab-staging` |
| Secretos dedicados | `cka-account-staging-runtime`, `cka-lab-staging-tunnel` |
| Entrada del bundle Identity compartido | Solo `consumers.cka-simulator` |

La retirada valida nombres, destinos DNS, dominios de Pages, ingress, etiquetas de Vault, proyectos Compose y hashes de política antes de borrar. Un recurso ajeno bloquea la operación. Las rutas de los túneles pasan a 404 antes de su eliminación; Cloudflare exige que sus conectores estén detenidos. Puede repetirse el workflow tras una retirada parcial. Los secretos OCI pasan a `PENDING_DELETION` con dos días de retención; no confundir ese estado con borrado físico completado. Las copias históricas cifradas de Identity se conservan junto con el resto de su custodia; el consumidor activo queda revocado.

Recibos esperados: `CKA_RETIRE_HOST_VERIFIED` y `CKA_RETIRE_CLOUD_VERIFIED dns=0 pages=0 tunnels=0`. Hasta tener ambos no considerar completada la retirada. DNS puede tardar en desaparecer de cachés; la ausencia se comprueba mediante el inventario de la zona, sin dar por bueno únicamente un error HTTP público.

Los workflows de CKA anteriores conservan contratos/historial pero sus jobs operativos están desactivados. El código de provisión Identity rechaza `enable`; un deploy posterior no puede reactivar CKA desde la interfaz. La publicación GHCR del repositorio CKA también está desactivada.

Referencias API: [Cloudflare elimina un proyecto y todos sus despliegues](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/delete/), [el túnel debe carecer de conexiones activas](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/methods/delete/), [OCI programa la eliminación de secretos](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/vault/client/oci.vault.VaultsClient.html).
