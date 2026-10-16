# Chronicles web: isolated staging origin

The container at `ghcr.io/evilsysadmin/chronicles-web` serves the independent
**static staging landing page only**, not the playable Chronicles application.
The first release originates from the protected `evilsysadmin/chronicles-of-matthias`
`main` workflow `.github/workflows/web-publish.yml`. A successful build does
not mean OCI, Cloudflare or the game is deployed.

## Safe host-side procedure

1. Confirm the exact successful publishing run on protected `main`, its source
   SHA, multi-arch manifest digest and GHCR provenance/attestation using
   independently retrieved GitHub and registry evidence. Do not trust a pasted
   digest or a mutable `staging-<SHA>` tag as release accreditation.
2. On the **dedicated OCI staging host**, inventory existing host bindings,
   Cloudflare Tunnel origins and other Compose projects. Port 18082 must be
   unused and must not belong to Chess Studio or another application.
3. Set `CHRONICLES_WEB_IMAGE_DIGEST=sha256:<verified-64-hex>` in the host
   environment. Never commit credentials or inject this variable into
   `compose.yaml` for the Chronicles API.
4. Run `docker compose -f compose.web.staging.yaml config --quiet`.
   Only after attestation and host checks pass, use
   `docker compose -f compose.web.staging.yaml up -d --no-build`.
   This manages exactly one web service in the independent project
   `shadowops-chronicles-web-staging`; it does **not** modify the API or Chess Studio.
5. Check its health and read-only origin:
   `curl --fail --silent --show-error http://127.0.0.1:18082/`.
   Verify it contains `CHRONICLES OF MATTHIAS` and
   `todavía no es el juego`.
6. Separately configure the reviewed Cloudflare mapping for
   `staging.chronicles.shadowops.dpdns.org` to the verified staging
   origin, without replacing or changing any existing Chess Studio ingress.
   Verify external HTTPS response, correct host routing and the staging marker
   before recording live readiness.

No Cloudflare/DNS/Tunnel modification, SSH connection, remote Docker action,
production deployment, or live smoke is performed by this repository PR.
The separate production name `chronicles.shadowops.dpdns.org` remains inactive.
The independent frontend must later replace this probe with a real Vite-bundled
game before anyone can play Chronicles at this hostname.

## Verified host-side web admission (check-only)

Once an OCI operator has provisioned a trusted checkout of ShadowOps and
**read-only** GitHub evidence access on the adopted Ampere A1, run:

```sh
export CHRONICLES_WEB_IMAGE_DIGEST=sha256:<independently-retrieved-manifest-digest>
# GH_TOKEN must be a scoped, read-only GitHub API / attestation token.
python3 scripts/oci_web_staging_preflight.py \\
  --sha <full-protected-main-source-SHA> \\
  --digest "$CHRONICLES_WEB_IMAGE_DIGEST" \\
  --run-id <actual-web-publish-workflow-run-id>
```

This runs the full **stopped-container-aware** shared-A1 Docker collision
census, independently verifies the completed `web-publish.yml` source workflow
and both successful jobs, protected main/ancestry, Sigstore **signed** GHCR
provenance for the exact digest, the multi-platform manifest's ARM64 and AMD64
variants, and the hardened, isolated Compose configuration bound to
`127.0.0.1:18082`. On success it prints
`CHRONICLES_WEB_A1_VERIFIED_PREFLIGHT_OK`.

**This command is deliberately check-only.** It never pulls an image, starts
a container, creates public routing, or records a deployment receipt. It is
not permission to launch an unreviewed digest or reuse Chess Studio's
privileged host deploy wrapper. A separate restricted deploy controller and
post-start origin smoke must be validated before staging goes live.

## Dedicated root-owned host deployer (prepared, not installed)

The OCI Run Command account `ocarun` was **actually checked** in trusted-main
run [38885330529](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38885330529).
Its four observations were `docker=no repo=no wrapper=no gh=no`.
Oracle authentication alone does not give that account Docker permission.

ShadowOps supplies a root-owned **Chronicles web only** deployer in
`host/chronicles-web-deploy.py`, a fixed Compose policy, an isolated
sudoers allowlist, and one-time `host/install-chronicles-web.sh`.
The installer is **not run by CI or OCI Run Command**. It requires a
pre-existing operator-authorized privileged SSH/console session on the
existing A1, and a root-owned, clean ShadowOps checkout pinned to a reviewed
protected-main commit at `/opt/shadowops-infra`. The host administrator
runs this only after verifying the exact source commit:

```sh
sudo /opt/shadowops-infra/host/install-chronicles-web.sh <reviewed-40-char-SHA>
```

This installs a private Compose project rooted at
`/etc/shadowops/chronicles-web-staging`, a root-owned Python wrapper
at `/usr/local/sbin/shadowops-chronicles-web`, a fixed Docker-ownership
guard library, and one narrowly scoped sudoers entry for `ocarun`.
It does not grant generic sudo, the Docker group or permission to modify
Chess Studio. It does not touch an application container during bootstrap.

**After independent GitHub/GHCR/Sigstore release accreditation**, a separate
trusted-main deployment controller can call the fixed program through OCI
Run Command:

```sh
sudo --non-interactive /usr/local/sbin/shadowops-chronicles-web deploy sha256:<64 lowercase hex>
```

The wrapper itself permits **only** `deploy` with an immutable SHA-256 digest,
renders the installed root-owned Compose project, audits all Docker bindings
(including stopped containers), pulls only the fixed Chronicles web image,
starts only `chronicles-web` and checks its local landing-page marker.
Only after a passing local smoke does it atomically record the deployed
digest. A failed replacement has no success receipt and requires explicit
operator investigation or rollback; there is no claim of automatic recovery.

**Current status:** no authenticated host bootstrap has been executed,
the dedicated wrapper is not installed on OCI, and the Chronicles web origin
has not been deployed. The first real release, DNS/TLS and extraction of the
playable game are separate gates.

## Trusted-main OCI release controller — ready to wire, manual-only

ShadowOps owns `.github/workflows/chronicles-web-oci-release.yml`.
It is **manually dispatched** from protected `main` with the immutable source
SHA, GHCR manifest digest and completed source publication run ID. The
admission job has **no OCI secrets**: it verifies GitHub protected-source
ancestry, both trusted publish jobs, Sigstore provenance tied to the exact
source workflow, multiarch support and the independent hardened Compose
policy. Only when that succeeds may a second job use the OCI API credentials.

OCI Run Command sends the literal digest and an exact fixed
`sudo --non-interactive /usr/local/sbin/shadowops-chronicles-web deploy`
invocation to the **already adopted A1**. It targets no other host, exposes
no runtime credentials and demands an exact post-deploy smoke marker.
It never invokes Chess Studio's deploy wrapper.

The controller is currently **not executable to completion** until the
one-time, authorized root installation described above has installed the
restricted Chronicles-only host wrapper and sudoers. Running it prematurely
fails closed; passing offline CI checks does not constitute a deployment.
No Cloudflare routing or production change is included.

## Single-command operator bootstrap over the existing SSH tunnel

**No additional OCI tenancy IDs, API keys, vault transfers, or new SSH keys
are required** if the operator's existing Ubuntu SSH identity is already
authorized on the adopted A1 and has noninteractive `sudo`. On a Linux
operator workstation (e.g. Nobara), install `cloudflared`, `git`, and
`ssh` if absent, then use the exact reviewed ShadowOps `main` checkout.
From the root of that checkout:

```sh
# Record the exact 40-character protected main SHA (no branch name or tag).
sha="$(git rev-parse HEAD)"
host/bootstrap-chronicles-web-over-ssh.sh "$sha"
```

Optional non-default key: set
`CHRONICLES_OPERATOR_SSH_KEY=/home/<user>/.ssh/<existing-key>`; the
**private key stays on that workstation**. The script refuses stale SHA,
dangerous arguments, non-main commits and unknown remotes. It connects to
the existing operator endpoint
`ssh-chess-studio-staging.shadowops.dpdns.org` via
`cloudflared access ssh --hostname %h`, with normal SSH host-key
verification (no `StrictHostKeyChecking=no`). On the host it requires
existing operator `sudo -n`, clones/checks a root-owned, clean
`/opt/shadowops-infra` checkout of current upstream main, and calls the
fixed install helper. It does **not** deploy a container or change DNS.

This one-time operator bootstrap is intentionally **not** in GitHub Actions
and is not executable by the unprivileged OCI agent. If the operator's
existing SSH account cannot authenticate or use `sudo -n`, it fails
without granting new privileges. Once the fixed wrapper is installed,
ShadowOps' signed OCI release workflow can perform subsequent releases
without interactive SSH.
