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
