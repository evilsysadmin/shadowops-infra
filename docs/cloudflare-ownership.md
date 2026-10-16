# Cloudflare asset ownership for the Matthias ecosystem

**Target authority:** ShadowOps Infra. **Current operator:** Chess Studio for
existing Pages, DNS and its outgoing OCI Tunnel until an explicit ownership
cutover. Chronicles has a proposed independent Pages project `chronicles-staging`,
but absence is allowed until a live deploy has been proven.

Run the `ShadowOps Cloudflare · existing resource inventory` workflow manually
from protected `main` after setting in **ShadowOps Infra**:

- `CLOUDFLARE_API_TOKEN` — a Cloudflare API token with **read-only** permissions
  for the existing zone's DNS records and account-level Tunnel/Pages metadata.
- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account ID (Actions secret or variable).

The workflow reads only known hostnames in `shadowops.dpdns.org`,
the existing `chess-studio-staging` Tunnel and Pages projects
`chess-studio-staging` / `chronicles-staging`.

No API key is logged. DNS targets, tunnel IDs and token values are not printed.
Missing Chronicles records/projects are reported as pending; missing or ambiguous
Chess Studio staging identities are errors.

**There is no Cloudflare mutation in this iteration.** We will move the
reconciler from Chess Studio only once inventory matches reality and the new
implementation has a route-preservation test covering the existing staging API,
production API and SSH ingress. Never run two reconcilers for the same tunnel.
