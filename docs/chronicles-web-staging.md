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
