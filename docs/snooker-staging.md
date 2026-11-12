# Snooker of Matthias — Cloudflare Pages staging onboarding

Staging hostname: **https://staging.snooker.shadowops.dpdns.org**.
Source: **evilsysadmin/snooker-of-matthias**.
Infra owns dedicated Direct Upload Pages project **snooker-staging**, zone DNS,
Identity audience, protected staging credentials, publication and rollback.
This first infra iteration is **read-only**: it neither provisions, deploys,
grants access nor certifies that any Cloudflare asset is already present.

## Evidence and boundaries

- Source PR #1 is merged; the game builds `snooker-web-dist` and real desktop/mobile
  Chromium screenshots in its own CI. Green source CI is not a deployment.
- Source PR #2 adds hold/release Space power and viewport fitting. An exact
  green *main* SHA must be re-admitted before a future release.
- ShadowOps Infra issue #527 tracks activation: https://github.com/evilsysadmin/shadowops-infra/issues/527
- No backend/DB/VM/R2 is needed for this Three.js/Vite POC.
- No public staging/guest mode. All custom-host, production `pages.dev` and
  preview aliases must **fail closed** for anonymous/revoked sessions, wrong
  Identity issuer/audience and unavailable Identity.

## Read-only preflight

On PR, run the offline tests (no secrets required).
On protected Infra `main`, workflow **Snooker · staging Pages read-only inventory**
uses existing staging-environment Cloudflare credential custody to GET the exact
zone, Pages project, custom-domain and DNS identities. It *never* makes a
Cloudflare write or prints API tokens. It rejects foreign/mismatched project,
other-source integration, wrong Pages branch, unexpected aliases/custom domains,
duplicate DNS or nonproxied/wrong-target records.

```sh
python3 -m unittest discover -s tests -p test_snooker_pages_readiness.py -v
python3 scripts/snooker_pages_readiness.py plan
# Only inside a trusted staging operator environment with read credentials:
python3 scripts/snooker_pages_readiness.py inspect
```

An inventory receipt only means ownership was classifiable, **not** that
authentication works. Missing Cloudflare credentials stop the workflow
without creating anything.

## Exact-source admission

The independent `Snooker · verify current source main for staging` workflow
checks a *push* on `main` for its immutable SHA, successful physics/build and
real desktop/mobile Chromium steps, and the unique non-expired
`snooker-web-dist` with its GitHub-recorded SHA256 ZIP digest. Its validator
also rejects archive path traversal, symlinks, scripts outside `assets/`, huge
entries and source-supplied `_worker.js`; Infra owns the authenticated edge.

Run `python3 scripts/snooker_source_admission.py check-current` with an
independent GitHub read token to obtain a SHA/run/artifact receipt. Recheck
source HEAD immediately before any future publication. **Admission is not
deployment, authentication or an authorization to create Pages resources.**

## Subsequent incremental release gates

1. Prove exact current green game `main` SHA (unit/build/Chromium) and verify
   immutable dist artifact digest and safe extraction, not an unverified URL.
2. Explicitly register audience `snooker` in staging ShadowOps Identity only.
   Gate all Cloudflare edge entry points including Pages preview aliases;
   strict issuer/signature/audience/freshness, fail closed on revoked sessions.
3. Provision and/or claim only the dedicated project and proxied custom host,
   refusing all unexpected foreign DNS/Pages resources.
4. Publish a source-SHA-pinned, authenticated release through Infra using
   existing protected credentials, rechecking exact source/owner revision before
   any Cloudflare mutation.
5. Verify signed-in game/WebGL and 200 responses, anonymous/wrong-audience/
   revoked/Identity-down denial on domain and Pages aliases, desktop/mobile
   screenshots, immutable release receipt and rollback.

No unrelated Football, Chronicles, Chess, Portal or production resources may
be changed by Snooker onboarding.


## Identity service contract (default-off)

The candidate code now recognizes a `snooker` issuer audience and a pinned
staging HTTPS origin. Existing staging runtime consumers remain exactly those
provisioned in the independent Vault bundle. **No Snooker credential can be
provisioned by this increment**; the operator opt-in, Vault validation and
Pages edge service binding must follow in separately tested steps. A green
contract is not evidence of public Snooker login or staging publication.


## Explicit Snooker Identity provisioning (code path, not activation)

The protected `ShadowOps Identity · isolated staging operational handoff`
workflow now accepts `snooker_consumer: preserve | enable`. Default
`preserve` does not create the consumer. A deliberate `action=provision`,
`snooker_consumer=enable` on protected Infra `main` can append exactly one
independent `soc1_` proof to the existing staging Vault bundle; retries reuse
the same proof, preserve every other consumer and do not rotate database or
signing keys. Invalid input fails *before* cloud activity.

**Do not provision yet as an assumed consequence of merging.** The explicit
operator dispatch still needs to occur, followed by a tested Identity rollout,
separate Snooker Pages edge service binding and all-URL fail-closed smoke.
Never place the generated secret or full bundle in this repository or a log.


## Identity-gated Pages edge (not deployed)

`edge/snooker-identity-gate.mjs` is the Infra-owned advanced Pages Worker
and will be injected as `_worker.js` into the exact admitted Vite build only
during a future release. The app repository never holds the edge secret.
Unknown hosts and all `*.pages.dev` aliases return 404; the custom domain
returns an unauthenticated 401 login shell but never the app's HTML/JS/CSS.
Signed Ed25519 audience `snooker` tokens and live Identity freshness establish
a short-lived Secure/HttpOnly host-only cookie. Wrong audiences, revoked/expired
tokens and Identity outages fail closed. The independent Vault service proof
must be provisioned through the protected operator workflow and bound to Pages.

Offline tests do **not** prove Pages delivery, alias denial or an active login.
Future publication must enforce `fail_open=false` on both production/preview,
verify real deployed hashes and browser play, plus guest/revoked denial.


## Empty dedicated Pages project provisioning (manual only)

After inspecting that the `snooker-staging` project and its DNS do not belong
to another app, dispatch **Snooker · create private Pages project (manual only)**
from protected Infra `main` with the existing staging-environment Cloudflare
credentials. The workflow only creates/claims an empty dedicated Direct Upload
project and sets `deployment_configs.production.fail_open=false` and
`deployment_configs.preview.fail_open=false`, plus a public-routed HTTPS
fetch compatibility flag. A second GET confirms both settings. It does **not**
attach the custom domain, upload assets, configure service secrets or publish
any build. Missing credentials/foreign resources/unexpected settings abort.
Do not treat the empty project as a playable staging deployment.


## Immutable Pages delivery candidate (still offline)

`scripts/snooker_release_package.py prepare ZIP sha256:<digest> <source_sha> OUT`
accepts only a ZIP passing the exact-main source admission archive rules,
reuses the original `index.html`/Vite assets **without rebuild** and injects
only the reviewed Infra `edge/snooker-identity-gate.mjs` as `_worker.js`.
The generated `release.json` records original artifact digest, exact green
source SHA, authentication audience, per-file byte lengths and SHA256.
`verify` rejects edited worker/assets, extra files and mixed/foreign hashes.
The candidate is not a hosted website; the future publisher must securely
consume it without bypassing Identity and then smoke its live behavior.


## Protected manual staging publication

Workflow **Snooker · publish authenticated staging Pages (manual)** is only
authorized on Infra protected `main`, with existing staging environment
Cloudflare and OCI Vault credentials. It verifies:

1. Current Snooker `main` exact SHA, its green CI and immutable ZIP digest.
2. An explicitly provisioned `snooker` Vault service proof, and that deployed
   `id-staging` login recognizes the pinned Snooker return origin.
3. The ZIP's source digest and contents, then adds reviewed Infra `_worker.js`
   and hashes all release bytes; rechecks source and Infra `main` before writes.
4. Creates only `snooker-staging` Pages, fails closed for both production and
   preview, binds **only** `SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL` as a Pages
   secret, and uploads through pinned Wrangler.
5. Checks that live `snooker-staging.pages.dev` responds 404 **before**
   attaching the custom host or writing its proxied CNAME; rejects foreign DNS.
6. Requires guest denial on both custom host and alias, writes the pinned
   source SHA and digest to GitHub's run summary, never the service proof.

The manual release cannot start before the separate protected Identity
`provision` (with `snooker_consumer=enable`) and audited Identity service
`deploy` have succeeded. A successful guest-denial probe is **not**
proof that a real authenticated desktop/mobile WebGL session works: test a
normal signed-in account, refresh, logout and revocation before declaring the
full staging rollout accepted. Failed steps are fail-closed; do not bypass the
Worker, make aliases public, or modify other games' Pages projects.


## One-use staging resume after SSH Identity host repair (2026-11-09)

The first actual protected rollout reached OCI after the one-use request
[#541](https://github.com/evilsysadmin/shadowops-infra/pull/541) but stopped
before Pages because the root-owned Identity deployment wrapper rejected the
newly provisioned Snooker consumer. The read-only
[OCI fingerprint](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/identity-wrapper-fingerprint.yml)
confirmed `IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_BUNDLE`; the operator then
ran `host/bootstrap-identity-staging-over-ssh.sh` and received both required
installer success markers. The installer alone does not prove the currently
running host matches the repository or that a deployment has happened.

The new one-use request
`ops/snooker-staging/resume-after-identity-ssh-2026-11-09.json`
starts the
[protected resume workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-resume.yml)
**only on its first addition** to the exact current protected Infra `main`
base `f57d3190273dd3c07e387ee2e7e4425935e765a8`.
It first uses the existing fixed, read-only OCI agent fingerprint to demand
`IDENTITY_WRAPPER_FINGERPRINT_CURRENT`, including both executable and
bundle validator hashes. Any mismatch, unsafe host file, missing receipt,
unauthorized source change, or advanced main fails closed.

**Only after the live OCI fingerprint passes** does the staging-approved
job use its ephemeral GitHub Actions token to dispatch the already reviewed
[Snooker protected activation](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-activate.yml).
That workflow still independently validates CI, admitted signed Identity
image, actual protected provision/deploy receipts and private Cloudflare
Pages. No Cloudflare/OCI secrets are added to the activation workflow itself
and this request does not rearm on later pushes.

A green **resume** job is evidence of dispatch, not evidence of deployment.
The signed-in browser / mobile WebGL, guest denial and revocation checks
remain release-acceptance criteria. If protected main changes before the
single-use request is merged, stop and update its pinned base under review
rather than disable the guard.

## One-time activation request on PR merge (2026-11-09)

The original Snooker staging activation was stuck because no authorized
`workflow_dispatch` was sent from the GitHub UI. To initiate the first
activation directly from the repository's reviewed change, this single-use
request lives at `ops/snooker-staging/activate-2026-11-09.json`.

On its **first addition** to protected `main`, the path-filtered
[one-time activation request workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-request.yml)
enters the existing `staging` environment. The job refuses any unrelated
source changes, replayed/modified request file, different base commit,
repository or branch. With environment permissions, it sends a GitHub Actions
`workflow_dispatch` to the already-reviewed
[Snooker activation workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-activate.yml).

The child activation workflow and its separate Identity and Pages deployments
still require their existing staging approvals and independently validate
artifact/signature, current source, Identity live receipt and guest denial.
This request **does not** grant or replace a Cloudflare/OCI credential, and
does not activate Snooker on normal future pushes. A skipped or approval-waiting
job is not a deployed release. Follow the exact Actions run URLs and stop on
any failure; do not disable the private edge gate.

The request is deliberately tied to base Infra main
`bbdee7e1b83ab7d2b4688fdc94fc3e59192a7e7e`. If main advances before
this PR merges, the request will fail closed and must be deliberately reissued.
After the first successful request, leave the file untouched: modifications
or deletion cannot reauthorize it. Always complete authenticated
browser/WebGL + logout/revocation acceptance before declaring staging live.

## One-click protected activation from GitHub Actions

For operators without a local checkout or `gh`, use
[Snooker · activate protected staging (one click)](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-activate.yml)
on **`main`**, choose **Run workflow**, and approve the existing
**`staging` environment** when requested. This is **manual only**; merging a
PR, a green build, or pushing `main` cannot start the activation.

The entrypoint uses GitHub's short-lived `GITHUB_TOKEN` with `actions:write`
**only in the manually dispatched, staging-approved job**, and no Cloudflare,
OCI, GitHub PAT, or Identity secrets. It launches the exact same
`snooker_staging_operator.py --check` and `--apply` as the local operator,
with a strict Actions-only flag requiring the expected workflow ref, protected
`main` SHA and run identity. The children remain the existing independent
Identity provision / signed-image deploy / private Pages publish workflows,
each with its own environment approval and fail-closed checks.

The one-click workflow fails if any child run cannot be uniquely identified,
fails CI, skips its actual protected mutation job or fails the guest-denial
smoke. It never substitutes a successful workflow status for a successful
deployment job. A platform-assigned Actions actor different from the strictly
expected `github-actions[bot]` also causes a fail-closed stop for investigation,
rather than accepting an ambiguous dispatch.

After a successful first activation, still perform a real **signed-in**
desktop/mobile WebGL smoke, refresh, logout and account/session revocation
before marking #527 completed. For more control or CLI debugging, the local
`--check` / `--apply` path below remains supported.

## One-command protected operator activation (optional)

The manual GitHub Actions steps above remain authoritative. To avoid three
separate UI dispatches, a trusted human operator with the **GitHub CLI** already
authenticated to an Actions-write account may use the auditable, locally run
helper. It does **not** embed, read or print Cloudflare, OCI or Identity secrets.

From a checkout of `shadowops-infra`, with Python 3.10+ and `gh`:

```sh
python3 scripts/snooker_staging_operator.py
# Read-only: discovers last actually published Identity image (not just green CI).
python3 scripts/snooker_staging_operator.py --check
# Explicitly authorize the existing staging environment workflows:
python3 scripts/snooker_staging_operator.py --apply

# Optional override only if an operator has independently verified an image:
python3 scripts/snooker_staging_operator.py --check --identity-sha <40-hex-admitted-identity-sha>
```

The first command is a static read-only plan. `--check` runs a **live,
read-only preflight before any Vault/Cloudflare mutation**: it independently
re-admits the current game's exact green `main` CI and SHA256-bound Pages ZIP,
checks the trusted GitHub operator and both repos' unchanged `main` SHAs,
verifies the current staging Identity readiness, and **automatically selects
the newest proven published Identity image** from successful protected-main
`identity-service.yml` runs. Green CI alone is not accepted: the exact
publish job must have completed its actual GHCR image upload, attestation and
digest-receipt steps. It rejects an image older than either the Snooker
consumer contract or the currently running staging Identity. An explicitly
provided `--identity-sha` overrides discovery but must pass the same
non-downgrade gate. Missing publish evidence or an obsolete image fails
**before** provisioning. The protected deploy workflow additionally verifies
the image's real GHCR manifest, arm64 platform, signature/attestation,
required checks and SHA ancestry; discovery never substitutes for admission.

`--apply` runs this same read-only preflight first; only if it passes does it
dispatch the **existing protected** Identity `provision` (only
`snooker_consumer=enable`) then, if the deployed Identity does not yet
recognize Snooker, `deploy` with the specified immutable image source SHA.
It refuses a deployment older than the currently running Identity release
or older than the Snooker consumer contract. It lastly calls the existing
Snooker Pages `publish` workflow, which rechecks source CI and SHA, Pages
ownership, the protected Worker, alias guest denial and custom-host guest
denial before enabling DNS.

The helper requires a unique fresh run for the exact Infra `main` and the
same authenticated operator. It **waits for the specific protected job**, not
just a green workflow with skipped deployment steps. Any failure,
ambiguous dispatch, unexpected Infra/game SHA change, or missing live Identity
release receipt stops the sequence. You can inspect the reported Actions run
URLs to diagnose; do not disable protection or rotate other credentials.
Retrying after partial success is safe at the existing workflow contract
level, but the helper revalidates the live state before any new invocation.

**No operator approval is delegated to the helper.** Actions environment
rules, CI provenance and Cloudflare secret custody remain unchanged. Running
this script in ChatGPT without an authorized `gh` session does not activate
staging. Even after successful guest-denial checks, **human signed-in browser
and revoked-session validation remains a separate release-acceptance gate**.

## OCI root-only Docker diagnosis after the 2026-11-09 deploy failure

The first protected activation reached the admitted, signed ARM64 Identity
image, but the root-owned container deployment returned a generic
`IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError` in
[run 42630458811](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42630458811).
The subsequent OCI Agent probe returned `IDENTITY_CONTAINERS_DOCKER_INACCESSIBLE`
in [run 42632260078](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42632260078).
**That marker is not evidence that Docker or the IdP is down:** the agent user
`ocarun` deliberately cannot access root's Docker socket.

The repair retains that isolation. Only the root-owned
`/usr/local/sbin/shadowops-identity-staging status` operation is added to
the existing sudoers allowlist for `ocarun`. It runs fixed `docker info`,
`ps`, and `inspect` *state/health only*, restricted by exact Compose project
and three service labels, returning finite sanitized statuses. It neither
executes inside containers nor reads logs, mounts, private config or secrets.
The OCI agent is granted no general Docker/shell privileges.

**After this change is reviewed and merged, the installed host wrapper must
be deliberately refreshed before the probe can work.** From an already
authorized operator workstation with the existing SSH/Cloudflare Access route:

```sh
# Installs reviewed host policy only; no container start or Pages write.
bash host/bootstrap-identity-staging-over-ssh.sh
```

That command fetches and verifies exact protected Infra `main` on OCI, then
reinstalls the root-owned wrapper/sudoers with the existing trust checks.
It does not update Identity images or start/restart services. The host
fingerprint must be current again afterward.

Next use [ShadowOps Identity isolated container health (read-only)](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/identity-container-health.yml)
on `main` and inspect the **probe job**, not just an offline green contract:
`IDENTITY_CONTAINER_STATUS identity-mongo=... identity=... identity-tunnel=...`.
A `missing`, `exited`, `restarting` or `unhealthy` service is the
next debugging target; a Docker-denied/unknown receipt means stop and inspect
the narrowly scoped installation or host reachability. Never infer readiness
from a green tests-only workflow.

Only once the actual Identity boot/health failure is corrected, re-run the
[manual protected Snooker activation](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-activate.yml).
That must independently publish private Pages, attach the exact proxied DNS,
and verify guest denial. Finally prove **signed-in** desktop/mobile WebGL,
login/logout and revocation on the custom domain before accepting issue #527.

No automatic staging deployment, DNS write, secret change, Identity restart or
approval is performed by this diagnostic PR.

## Fixed Identity deploy stage receipts for Snooker rollout (2026-11-09)

After the original protected release returned only `IDENTITY_STAGING_DEPLOY_BLOCKED
type=DeployError`, the OCI diagnosis rerun
[42643741461](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42643741461)
also failed with `IDENTITY_CONTAINER_PROBE_BLOCKED type=InventoryError`.
Neither result authorizes a guess about whether Mongo, the main Identity service,
or its tunnel is at fault; **the reviewed OCI wrapper needs installing**.
This remains a DNS/Identity blocker, not a Vite build failure.

The root-owned host deploy code now classifies only the following **finite,
secretless failure phases**: `source` (host and policy), `custody` (Vault,
backup, credentials, ownership), `images` (Compose and digest),
`database-start`, `database-ready`, `database-bootstrap`, and
`services-start` (Identity/tunnel start and wait). A failure emits a
single `IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=<code>`
marker instead of a private Docker/OCI exception. The CI parser accepts only
those fixed phase names and remains compatible with the legacy generic marker.
It refuses to copy arbitrary stdout, stderr, Vault data or Docker output to
the logs. A phase marker is diagnostic information, **not** proof of service
health or release acceptance.

Once reviewed and merged, the authorized operator should refresh the host
**once from the latest protected main**:

```sh
git pull --ff-only
bash host/bootstrap-identity-staging-over-ssh.sh
```

Then use the existing [read-only Identity container probe](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/identity-container-health.yml)
on protected `main`. If it shows a missing/unhealthy Identity container,
investigate that service; if the stack is ready, the operator may explicitly
start the existing [protected Snooker activation](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/snooker-staging-activate.yml).
If activation still fails in a root deploy stage, investigate the finite phase
rather than restarting services or weakening the edge. **Do not rerun the
original stale release run**; re-admit the current signed image and current
Snooker `main` through the canonical workflow. Custom DNS and signed-in
desktop/mobile WebGL acceptance must remain last and separately verified.

## Root deploy custody failure: precise bounded follow-up (2026-11-10)

The protected [Identity deploy 42729097483](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42729097483)
passed signed ARM64 image admission but failed on the real OCI host with
`IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=custody`.
The earlier [read-only host check 42726012827](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42726012827)
confirmed all three existing Identity containers are running, with Mongo and
Identity healthy. **Do not infer that a new Identity release or Snooker Pages
is live from the existing healthy containers.** The one-use activation
[42728704144](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42728704144)
stopped before Pages publication, as intended.

The root wrapper's unchanged custody operations now emit a more precise,
fixed, nonsecret phase on error: `custody-atlas` (Atlas takeover marker),
`custody-host` (shared A1 isolation), `custody-identity` (Docker labels,
volume/network ownership), `custody-vault` (validated Vault bundle),
`custody-backup` (recent authenticated local backup), or `custody-config`
(local sealed configuration preparation). No underlying host exception,
container logs, private paths, secrets or environment values are exposed.
OCI accepts only this finite list and retains legacy `custody` compatibility.

**Next required host step:** an authorized SSH/Cloudflare Access operator must
refresh the reviewed installed root wrapper from **current protected main**
via the existing `bash host/bootstrap-identity-staging-over-ssh.sh` procedure.
A GitHub merge alone does not update the root-owned OCI installation.
Then use a **freshly admitted, protected** Identity deployment through the
existing staging workflow, not a rerun of the old pinned run. Investigate the
resulting custody subtype before any further change. In particular, only a
verified `custody-backup` result warrants investigating the existing
encrypted-backup policy; never disable backup, Atlas or ownership guards to
pass a release.

The Snooker Pages/DNS and authenticated browser/security acceptance steps
remain blocked until Identity's actual release is verified ready.

## Diagnose Atlas takeover marker without changing the host (2026-11-10)

The [second protected Identity deploy 42787035056](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42787035056)
passed TLS/Mongo contracts and the signed ARM64 image admission but
**failed closed** with `phase=custody-atlas`. The exact fixed guard
in `host/identity-staging-deploy.py` refuses local deployment whenever
`/var/lib/shadowops/identity-staging/atlas-active` exists or is a symlink.
The source repository contains **no** authorized automatic creation/removal of
this marker, and the Atlas Compose file is still described as a candidate.
Neither proves whether the live Identity container uses local Mongo or Atlas.

The next step is an **operator-only, read-only** check through the *existing*
human Cloudflare Access SSH/sudo route. Use the latest protected Infra main
checkout on the authorized workstation:

```sh
git pull --ff-only
bash host/inspect-identity-atlas-mode-over-ssh.sh
```

This wrapper refuses any input arguments or an outdated/non-Infra checkout.
It sends one fixed, reviewed stdlib-only Python script on stdin to the pinned
OCI host via `sudo --non-interactive python3 -I -`. It does not install,
delete, restart, rotate, mutate Docker, or read configuration contents.
It checks only the marker's existence/ownership/mode, exact Compose identity
container labels, **the source of its already-mounted config file**,
exact network names and the container state. No Docker Env, Vault material,
URI, tokens, raw host mounts or private paths are printed.

The entire expected receipt has this nonsecret shape:
`IDENTITY_ATLAS_MODE marker=present|absent config=local|atlas container=running|exited|created|restarting|paused|dead`.
Unrecognized configurations and unsafe marker states fail closed with a
finite `IDENTITY_ATLAS_MODE_BLOCKED reason=<code>` response.

Interpretation:
- `marker=present config=local`: marker and mounted local config appear
  inconsistent. **Do not remove the marker automatically.** The host operator
  must establish why it was placed and whether Atlas cutover/rollback is in
  progress before authorizing any narrowly scoped change.
- `marker=present config=atlas`: the Atlas-specific config is mounted.
  Do **not** run the local Mongo deployment path or edit the marker.
  Verify actual backend custody, backup/restore, egress and approved Atlas
  cutover before considering an Atlas-specific release.
- `marker=absent config=local`: the original guard should no longer be the
  blocker; investigate concurrent operator changes and revalidate current
  protected source and health before any deployment.
- Any other receipt: stop, keep the private service untouched, and investigate
  through the authorized operator.

The config mount alone cannot prove which database URI the service is using
or whether a cutover is safe. The current Snooker activator intentionally
uses the protected local Identity release and **cannot** bypass this guard.
Snooker Pages/DNS and signed-in WebGL acceptance remain pending.

## Public Identity audience probe independent of host custody (2026-11-10)

A protected Snooker activation may deploy Identity **only if** the already-live
`https://id-staging.shadowops.dpdns.org/login?app=snooker` endpoint does not
advertise the exact Snooker callback. The last actual signed deploy
[42787035056](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42787035056)
failed safely at `custody-atlas`; it must not be retried until the Atlas
takeover marker is understood.

The `snooker-identity-public-probe.yml` workflow performs an independent,
read-only public HTTPS observation from protected main, using no OCI, Vault,
Docker, Cloudflare or GitHub write credentials. The result has a fixed shape:

```text
SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present|unavailable-or-unrecognized release_sha=<40hex>|unavailable
```

The exact output is one line (the alternatives above are documentation, not
an emitted receipt). The login check tests the existing full callback for
Snooker; the release check validates the public Identity source receipt.
A successful workflow job only proves **the observation ran**, not that
the login target was ready. Check the actual finite receipt. A present login
target is still insufficient without the independent **OCI Vault Snooker
service proof**, private Cloudflare Pages binding, guest/alias denial,
authenticated WebGL and session revocation. Neither a reachable `/readyz`
nor a currently healthy container proves that the required audience exists.

**Atlas host configuration is separate evidence.** The authorized operator
must relay the one-line `IDENTITY_ATLAS_MODE ...` receipt from
`bash host/inspect-identity-atlas-mode-over-ssh.sh`; the public probe cannot
see the private takeover marker or determine whether Atlas cutover is active.


## Operator-approved SSH fallback after OCI Run Command ServiceError (2026-11-10)

The signed Atlas Identity source `4a48dff49c4a77703c6f4b164120d3cef8e77e76`
and immutable digest `sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91`
passed protected image admission in both [42819583082](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42819583082)
and [42823811617](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42823811617).
Each actual Atlas release step failed in OCI with `ServiceError` before the
root operator receipt. The independent read-only OCI creation audit in
[42821843479](https://github.com/evilsysadmin/shadowops-infra/actions/runs/42821843479),
re-run after the second failure, reported
`IDENTITY_ATLAS_COMMAND_AUDIT created=not-observed-since-attempt`.
The public read-only probe likewise still reported the previous release
`34d5aa2f4db3f522336a150266ac21f94d3ce95f` and no Snooker callback.
**No new root release command was created by the failed API attempts.**

The authorized operator previously installed the reviewed Atlas-only root
release wrapper through `host/bootstrap-identity-staging-over-ssh.sh`, receiving
both `IDENTITY_STAGING_OPERATOR_WRAPPER_INSTALLED` and
`SHADOWOPS_SHARED_IDENTITY_STAGING_WRAPPERS_INSTALLED`. After reviewing the
latest protected main and only when deliberately approving this staging-only
release, the same trusted human SSH route is available without relying on
the failing OCI Run Command service:

```sh
git pull --ff-only
bash host/identity-staging-atlas-release-over-ssh.sh
```

This script refuses parameters, unknown Git origins, dirty/outdated checkouts,
and all mutable image references. It sends only the previously admitted
digest/source SHA to the root-owned
`shadowops-identity-atlas-deploy` through the fixed Cloudflare Access SSH
host. The host still enforces existing Atlas-only custody, current public SHA,
same-cluster recent authenticated backup and verified quarantine restore,
preflight, exact new runtime/public SHA and Snooker callback, and the
journalled previous-image rollback. It never deletes `atlas-active`, changes
the database, touches the tunnel, deploys another product or publishes Pages.

Only the exact `IDENTITY_ATLAS_DEPLOY_OK source_sha=... digest=...` and
`IDENTITY_ATLAS_SSH_PUBLIC_SNOOKER_READY` markers confirm this
manual Identity release. A failure or unexpected receipt is **not**
authorization to repeat it: establish host/container and private
`atlas-deploy-pending.json` status before trying again. The script deliberately
does not log SSH stderr, secrets or private host output.

Even after Identity succeeds, the separate
`snooker-pages-release.yml` protected staging workflow must provision/bind
private Pages, publish the current signed Snooker CI ZIP, activate DNS only
after anonymous alias denial and verify guest, authenticated and revoked
session behavior. Identity SSH release alone is **not** a live Snooker deployment.

## Atlas Snooker audience: isolated candidate config (rollback-safe)

If the protected host inspection reports `source=absent atlas=absent` after
`candidate-audience rollback=verified`, do **not** overwrite either existing
`service.json` or `atlas-service.json`: the previous healthy Identity image
does not recognize Snooker and must keep its exact old configuration.

The existing protected staging Identity workflow has an explicitly authorized
`action=provision, snooker_consumer=enable` to add **only** the independent
Snooker consumer to the existing Vault bundle, preserving other consumers and
signing material. Provisioning alone does **not** update either host config.

After that action has genuinely succeeded, the distinct protected
`action=atlas-snooker-config` runs the fixed root operator against the current
Vault bundle. It requires the exact old healthy public Identity SHA, trusted
Atlas paths and lock, absent transition checkpoint, preserved original local
and Atlas config fields, and **only** a new Snooker consumer in Vault. It
creates or verifies `atlas-snooker-service.json` as a separate private
`0400` file owned by uid 65532; it never overwrites the legacy two files,
restarts a container, contacts Mongo, or changes Cloudflare. Unknown changes
abort without writing. A failure receipt does **not** certify provision or
release success.

**Important:** the existing Atlas Compose/release policy still mounts the
legacy `atlas-service.json`, and no candidate deployment is authorized by this
preparation alone. A separately reviewed image-pinned release policy must
select the isolated Snooker config **only for the new image** and re-select
the unchanged legacy config on rollback. That change requires another PR,
complete CI and independent explicit activation; never work around it by
editing the mounted legacy config or disabling the audience check.

## Scheduled reconciliation and drift audit

The protected `Snooker · publish authenticated staging Pages` workflow polls green game
`main` on an off-hour 15-minute cadence, attempting publication only when
the existing fail-closed admission determines that Pages is not serving the
exact source SHA. GitHub scheduled workflows are **best effort** and can be
delayed or skipped under Actions load; no recent schedule run must never be
misinterpreted as an up-to-date deployment.

Every actual scheduled run now also performs the independent, **read-only**
guest-denial and canonical source-SHA audit after the publish job, including
when that job reports "already current". On any mismatch, the scheduled
workflow fails instead of silently reporting success. The same audit continues
to run after explicit dispatch and Infra main pushes. It requires the existing
protected `staging` environment and cannot bypass Identity; no new cloud
credentials, external tokens or deployment privileges are introduced.

If the scheduler does not run, an authorized operator should use the
existing manual `workflow_dispatch` on protected Infra `main`, inspect the
`publish` and `post_publish_audit` jobs, and verify that the deployed source
SHA agrees with the latest green game `main`. A green game CI alone does not
establish a deployed release.

## Independent half-hour drift watchdog (best-effort GitHub scheduler)

The normal protected Snooker Pages publisher polls exact green game `main` every
15 minutes. GitHub Actions scheduled events can nevertheless be skipped or
severely delayed, even away from the top of the hour. A second, deliberately
independent **read-only drift watchdog** polls at minutes 07 and 37. On an
authorized Infra `main` push modifying its own implementation, it also runs
once so the new code receives a real no-op check before relying on its cron.

The watchdog reads the canonical **production** Pages SHA, verifies existing
private Pages and DNS ownership, tests the live Identity callback and anonymous
custom/alias denial, and reads the current game `main` SHA. A match is a cheap
no-op and does **not** require historical CI ZIP retention. Only when source
and deployment differ does it re-admit the exact green `main` CI, unique
SHA256-bound unexpired artifact and unchanged source HEAD. A guarded Actions
job with `actions:write` restricted to protected staging may then dispatch
**only** `snooker-pages-release.yml` on the exact Infra `main`; it first
rejects stale Infra or game SHAs and skips requests when the protected
publisher is already active.

The watchdog cannot deploy assets, change DNS, edit Identity or bypass the
original publisher's independent source/artifact/Vault/guest/commit checks.
All cloud operations, policy, staging approval, release convergence and
read-only post-publish audit still happen exclusively inside that original
protected workflow. A red game `main`, transient failed network probe, expired
artifact or unsafe ownership blocks dispatch and reports failure.

Both schedules remain **best effort**, not a hard deadline or a guarantee that
GitHub will emit either event. Operators can use the watchdog's manual
`workflow_dispatch` or the existing protected publisher workflow on Infra
`main` when runs have stopped; they must inspect actual publish/audit jobs,
not just a green watchdog. No extra PAT, GitHub App installation, cloud
credential or anonymous staging mode is needed. Signed-in desktop/mobile
WebGL acceptance remains a separate human-operated gate.

## Signed-in live Snooker browser acceptance (explicit protected operator)

Workflow: **Snooker · real authenticated staging browser journey**,
`.github/workflows/snooker-live-browser-journey.yml` on protected Infra `main`.
It does not run authenticated login on PRs or ordinary pushes. PRs and pushes
run offline contracts only. A reviewer/operator can manually dispatch it
under the existing `staging` environment approval after configuring two
**staging-only** environment secrets, `SNOOKER_E2E_USERNAME` and
`SNOOKER_E2E_PASSWORD`, for an **existing dedicated test account**. This
workflow intentionally will not create untracked permanent accounts in
Identity (the browser service provides register/recover/logout but no
self-service account deletion). Both secrets are mandatory; missing secrets
fail the live job instead of producing a misleading green result.

The live run first independently verifies anonymous custom-domain and Pages
alias denial, exact Cloudflare canonical production SHA = current game `main`,
and immutable source pinning. The browser then uses the real central Identity
login UI and the production Snooker Worker handshake, without mocked APIs,
manual cookies, fabricated JWTs, insecure TLS or proxy overrides. At desktop
1440×900 and mobile 390×844 it proves genuine authenticated
`/api/snooker/session`, the pinned private `release.json`, actual WebGL felt
pixels, a real shot, F5/reload and newly initialized game, and finally Identity
server-side revocation and Snooker cookie logout. With a still-present edge
cookie, revocation must immediately deny protected files. After logout the
login shell must return and no WebGL assets may be served to a guest.

Game screenshots are captured **only after authentication**, with short
retention; the Identity login, password, cookies, user subject, JWT, recovery
codes and secret values are never photographed or logged. The workflow
rechecks published SHA after play and does not write to Cloudflare, DNS or
Vault. The current POC deliberately resets an unfinished rack on F5; this
journey asserts that behavior rather than claiming game-state persistence.

A green offline PR or postmerge contract run is **not** a completed signed-in
live test. A real live acceptance requires an actual successful
`workflow_dispatch` with the two dedicated test-account secrets and a green
`live` job. Do not trigger on a personal user account or invent credentials.
