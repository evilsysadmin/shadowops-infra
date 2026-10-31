# Chronicles staging — current release and recovery runbook

Updated: 2026-10-20. This is the **current** operational entry point for
`chronicles-of-matthias` staging. The older
[`chronicles-pages-handoff.md`](chronicles-pages-handoff.md) records the
migration history, including obsolete `/react/` and manual-bootstrap stages;
do not follow its historical instructions as if they describe today's pipeline.

## Ownership and boundaries

- `evilsysadmin/chronicles-of-matthias` owns game source, CI, frontend build
  inputs and API image.
- `evilsysadmin/shadowops-infra` alone owns staging deployments: isolated
  OCI API, Cloudflare Pages `chronicles-staging`, DNS/TLS verification and
  release artifacts. Nothing here authorizes changing Chess Studio or
  promoting a staging SHA to production.
- Infra receives source-CI dispatches when configured and also polls hourly.
  Changes to this file are a **release request**, not proof of deployment.

## Comprobar el wrapper OCI sin instalarlo (operador)

**Alternativa sin SSH de operador:** en GitHub Actions, abrir
[ShadowOps OCI · existing host probe](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/oci-host-probe.yml),
seleccionar `Run workflow`, rama protegida `main`, y `probe:
chronicles-wrapper`. Esta ejecución **manual** utiliza el OCI Run Command
existente con un script fijo y no privilegiado: solo comprueba propietario,
permisos y SHA-256 del wrapper en el A1. No lee Vault, no ejecuta Docker y no
instala nada. OCI sí crea un registro de ejecución de comando.

El workflow compara el hash con el archivo del checkout validado de
`main`; el resultado `CHRONICLES_API_WRAPPER_CURRENT` indica coincidencia.
`..._OUTDATED`, `..._MISSING` y `..._UNSAFE` se muestran sin exponer
ningún log remoto y hacen fallar el job para evitar un falso verde. Una
salida malformada o un `main` obsoleto también bloquean el diagnóstico.
Este probe no habilita un despliegue, ni sustituye el procedimiento de
instalación autorizado.

La instrumentación de fases de OCI de `host/chronicles-api-deploy.py` se
activa **solo cuando ese fichero está realmente instalado en el A1**. El
merge a `shadowops-infra/main` no lo instala, ni un workflow verde acredita
que el wrapper del host sea actual.

Desde el checkout local del operador Linux, con SSH + Cloudflare Access
configurados, ejecutar:

```bash
bash host/bootstrap-chronicles-api-over-ssh.sh --check
```

Opcionalmente, se puede añadir el SHA completo de `shadowops-infra/main`
como argumento. El script primero lo valida contra el `main` remoto, obtiene
el hash del archivo de ese commit sobre **el equipo del operador** y compara
con el wrapper instalado a través del túnel SSH existente, **sin sudo ni
mutaciones remotas**. No lee ni imprime variables de Vault, ni invoca Docker.

- `CHRONICLES_API_WRAPPER_CURRENT` (exit 0): el archivo instalado coincide.
- `CHRONICLES_API_WRAPPER_OUTDATED` o `..._MISSING` (exit 3): requiere
  actualización manual para obtener las nuevas métricas.
- `CHRONICLES_API_WRAPPER_UNSAFE` (exit 65): no continuar hasta revisar el
  propietario, permisos o posibles enlaces simbólicos.

La instalación sigue siendo una operación **distinta y explícita** del
operador, mediante el mismo script **sin** `--check`, que verifica de nuevo
el commit protegido antes de instalar. Ni el modo `--check` ni los checks de
GitHub ejecutan esa instalación. Después de cualquier instalación autorizada,
repetir `--check` antes de utilizar las métricas de fases.

## Staging state machine

1. **Source CI ready:** all three required Chronicles source-main checks
   succeeded for one immutable, current SHA. An older or pending SHA must
   not be published merely because its CI was green in the past.
2. **API verified:** the OCI deploy finishes public health, proves that
   `/api/release.build` matches the admitted source SHA, and passes player-path
   smoke before writing `chronicles-api-staging-<SOURCE_SHA>`. Pages checks the
   exact API artifact, its completed successful Infra API workflow run on
   `main`, the current public `/health` and `/ready` endpoints
   **and** `/api/release.build` matching that exact source SHA before Pages
   work begins. A healthy API running a different revision cannot authorize
   Pages, even if a valid historical API receipt exists.
3. **Pages verified:** Pages publishes the exact SHA (or, if the exact SHA is
   already live, retries public checks **without** rebuilding/redeploying).
   It checks custom-domain HTTPS, public `release.json.build`, desktop/mobile
   Chromium and the real login/first-hour browser journey, then rechecks that
   Chronicles source `main` has not advanced.
4. **Receipt:** only after these checks does Infra upload
   `chronicles-pages-staging-<SOURCE_SHA>` with `source-sha.txt` and
   `evidence.json`. Evidence includes the live manifest, linked API receipt,
   the workflow run and `verification_mode` (`new_publish` or
   `existing_live_build`).

A green PR, skipped deployment job, successful dispatch, or historical
artifact alone does **not** establish current public staging readiness.

## Qué ha cambiado en staging

Cada Pages release **verificada** genera el documento
`RELEASE_NOTES.md` después de los smokes y del guard de freshness.
Un job final, **Chronicles staging · release notes**, descarga el
recibo canónico **de la misma ejecución y del SHA exacto** y publica el
Markdown en el [Summary de la ejecución completa](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/chronicles-pages-release.yml).
GitHub agrupa y ordena los resúmenes de los jobs por finalización, de modo
que este informe aparece al final del run, no perdido en los logs.
El generador `scripts/chronicles_staging_changelog.py` solo se ejecuta
después de los smokes y del guard de freshness. Usa las evidencias de Pages previamente
verificadas, compara el SHA anterior contra el nuevo en el repositorio fuente
y enlaza las PR fusionadas asociadas a los commits. El artefacto
`chronicles-pages-staging-<SHA>` incluye `changes.json` y referencia esos
mismos datos desde `evidence.json`, cuando están disponibles.

### Consulta rápida sin leer logs

1. Abre [ShadowOps · Chronicles staging Pages release](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/chronicles-pages-release.yml)
   y selecciona una ejecución que haya verificado una **nueva** generación.
2. Entra en **Summary** de ese run y baja hasta el bloque final
   **Chronicles staging · release notes**. El informe se muestra **inline**
   sin descargar ni abrir el job: SHA anterior/actual, número de PR y commits,
   enlaces a staging y a la comparación, y PR incluidas; los commits se
   mantienen plegados.
3. Abajo, en **Artifacts**, descarga
   `chronicles-staging-release-notes-<SHA>`. El ZIP lleva
   `release-notes.html` (abre con doble clic, sin servidor ni dependencias)
   y `RELEASE_NOTES.md`. Es una copia amigable del mismo contenido,
   sin permisos de despliegue.
4. El recibo canónico `chronicles-pages-staging-<SHA>` también conserva
   ambos formatos legibles, además de los JSON de evidencia.

El job final solo se ejecuta si el job Pages termina correctamente y el
paso de freshness verifica la generación exacta. Un job de PR o un intento
omitido no crea este bloque. Una reverificación del mismo SHA, si llega a
realizarse, se identifica como tal y no inventa nuevas PR. Los artefactos caducan a los 90 días;
el informe descargable es comodidad, **no** historial permanente ni fuente
de verdad alternativa.

La detección de historial tiene límites explícitos: receipts de Actions
caducan a los 90 días, la búsqueda de baseline examina como máximo
800 artefactos recientes y el detalle de commits se limita a 60 entradas.
La ausencia de baseline, los cambios de historia no lineales y las
consultas incompletas se indican sin fabricar novedades. La misma
generación reverificada aparece como **sin cambios nuevos**.

**El changelog es informativo, no es un gate de despliegue ni prueba de
release por sí solo.** Una incidencia de lectura en GitHub no debe romper
los smokes ni impedir guardar un recibo realmente verificado. Para saber
qué está sirviendo el entorno ahora, contrastar siempre `release.json`,
`/api/release` y los recibos de API/Pages exact-SHA.

## Recovery without unnecessary mutations

- **Nothing new:** verified Pages receipt **plus matching public** manifest
  skips rebuilding; the API skips only with a trusted receipt **and** live
  public `/health` and `/ready` responding (with one retry per endpoint).
  Check the actual run before claiming a deploy happened.
- **Trusted API receipt but public health fails:** the API admission fails
  closed and leaves the deployed container untouched. The staging watchdog
  reports persistent public failures. Investigate before a deliberate manual
  redeploy; a single timeout is not grounds for automatic mutation.
- **Trusted API receipt but wrong public API SHA:** an unambiguous different
  40-hex `/api/release.build` allows the usual source-CI/attestation-guarded
  staging redeploy. Missing, malformed or unreachable identity is inconclusive
  and does **not** automatically mutate OCI. Pages never admits a mismatch.
- **Pages artifact missing but correct SHA already live:** the next admitted
  Pages staging run skips build/Cloudflare mutation, repeats public smoke, and
  issues a verified receipt only on success.
- **Live manifest differs from current green source SHA:** the admission path
  is allowed to republish the current SHA, provided the exact API prerequisite
  and ownership gates hold.
- **Source advances mid-run:** pre-mutation, immediately pre-Wrangler and
  post-smoke guards block an obsolete Pages receipt. A new admitted run must
  validate the newer SHA.
- **API artifact missing, CI pending, Cloudflare ownership conflict or
  smoke failure:** treat as **not verified**; inspect the failing gate. Do not
  manually manufacture a receipt or assume retries succeeded.

## How to verify a release

Review the actual workflow runs in
[ShadowOps Infra Actions](https://github.com/evilsysadmin/shadowops-infra/actions):

- `ShadowOps OCI · Chronicles API` — requires the exact-SHA API receipt and
  successful public/player-path smoke.
- `ShadowOps · Chronicles staging Pages release` — requires the exact-SHA
  Pages receipt, successful live HTTPS manifest check and browser smoke.
- `Watch Chronicles staging health and release drift` — reports persistent
  public health/release drift, not a new deployment.

For an independent read-only manifest check:

```bash
curl -fsS 'https://staging.chronicles.shadowops.dpdns.org/release.json' \
  | python3 -m json.tool
```

Compare its `build` to the **actual current Chronicles source main SHA**
and the SHA suffix of both trusted release artifacts. A manifest match alone
does not prove that the API or browser smoke completed successfully.

## Measured staging performance

Baseline from successful Infra staging runs on 2026-10-20:
[API run 39473792986](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39473792986)
spent about 241 seconds in the OCI deployer step, while
[Pages run 39473797991](https://github.com/evilsysadmin/shadowops-infra/actions/runs/39473797991)
spent 309 seconds waiting for the same-SHA API, 20 seconds publishing to
Pages, 8 seconds building and 91 seconds running Chromium smoke.

The API wait overlaps the OCI deployment; **do not add the 309 seconds to
the API run as though it were independent work**. On the next actual API
deployment, the safe `CHRONICLES_API_OCI_PHASE_SECONDS` marker splits the
OCI step into preflight, command dispatch and remote execution seconds.
The marker contains fixed labels and integer timings only, not OCI IDs or
secret material. It is observational and never authorizes deployment.

The controller also observes OCI's own command lifecycle while polling.
When it actually sees `IN_PROGRESS` before a terminal result, it emits
`CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=N active=M`.
These are **poll-time estimates**: `pre_active` is elapsed time from command
submission until the first observed `IN_PROGRESS`, and `active` is the
elapsed time from that observation to the terminal result. They are **not**
exact server queue time or Docker runtime; the agent may transition between
polls. If `IN_PROGRESS` is never observed, the line is omitted rather than
inventing a split. Fixed-label timings also help diagnose failed terminal
runs, but never echo the remote command output.

The same OCI poll response has a separate `delivery_state` field. If
`ACKED` is observed **before** terminal, the controller reports
`CHRONICLES_API_OCI_DELIVERY_OBSERVED_SECONDS before_ack=N after_ack=M`
in safe logs and the Actions Summary. ACKED establishes only that the Oracle
Cloud Agent received the command, **not** that the host started or completed
running it. Those durations are bounded polling observations, not precise
delivery times. A command seen as ACKED only when already terminal does
**not** qualify for this split; no timing is inferred. No new OCI requests,
host reads, credentials or deployment commands are needed.

The independent host-phase line, available only after a separately installed
updated wrapper and successful smoke, reports guard, Vault, Compose, image
pull, startup and health phases. Do not attribute a long OCI lifecycle
to Docker until that host-phase evidence is available.

When a real OCI command reaches a terminal result, the controller also
appends an **OCI deployment timing** section to that job's GitHub Actions
Summary. It includes only allowlisted controller/lifecycle timing lines,
and the fixed-format host phase line if the installed wrapper reported one
on a fully verified successful smoke. Terminal failures are labelled
**not verified**; never mistake their timings for successful deployment.
The summary has no OCI stdout, command IDs, Vault identifiers, image digests
or runtime credentials. An unavailable job summary does not block or
retroactively validate the deploy.

If the controller reaches its 650-second OCI polling deadline without a
terminal agent response, it still records elapsed local phases and any
actually observed `IN_PROGRESS` split with **Verified wrapper smoke: no**.
A timeout does **not** create a release receipt, imply that OCI succeeded,
or guess the host's activity. It remains a failed deployment; the diagnostic
does not extend the deadline or issue additional OCI calls.

The staging Chromium download cache is keyed to the resolved Playwright
version. Compare warm-cache browser smoke against the above cold baseline
before claiming an improvement; both browser journeys remain mandatory.

## Manual versus automatic operation

`workflow_dispatch` with manual force/redeploy retains the explicit
republication behavior; automatic/`only_if_new` requests are idempotent.
Promotion to production is separate, manually authorized and requires an
explicit vetted SHA. Never interpret a staging receipt as production approval.

Previous release-request SHA notes live in this file's Git history; they
are historical requests, not an instruction to redeploy those revisions.
