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

Cada Pages release **verificada** añade a su [GitHub Actions job summary](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/chronicles-pages-release.yml)
la sección *Chronicles staging · cambios de esta release*. El generador
`scripts/chronicles_staging_changelog.py` solo se ejecuta después de los
smokes y del guard de freshness. Usa las evidencias de Pages previamente
verificadas, compara el SHA anterior contra el nuevo en el repositorio fuente
y enlaza las PR fusionadas asociadas a los commits. El artefacto
`chronicles-pages-staging-<SHA>` incluye `changes.json` y referencia esos
mismos datos desde `evidence.json`, cuando están disponibles.

### Consulta rápida sin leer logs

1. Abre [ShadowOps · Chronicles staging Pages release](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/chronicles-pages-release.yml)
   y selecciona una ejecución que haya verificado una **nueva** generación.
2. La pestaña **Summary** presenta una tabla con SHA anterior/actual, número
   de PR y commits, enlaces directos a staging y a la comparación de GitHub,
   y una lista de las PR incluidas. Los commits van plegados debajo.
3. Abajo, en **Artifacts**, descarga
   `chronicles-staging-release-notes-<SHA>`. El ZIP lleva
   `release-notes.html` (abre con doble clic, sin servidor ni dependencias)
   y `RELEASE_NOTES.md`. Es una copia amigable del mismo contenido,
   sin permisos de despliegue.
4. El recibo canónico `chronicles-pages-staging-<SHA>` también conserva
   ambos formatos legibles, además de los JSON de evidencia.

Un job de PR, un intento omitido o una reverificación sin nueva generación
no publica un changelog de novedades. Los artefactos caducan a los 90 días;
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
