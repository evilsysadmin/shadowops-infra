# Chronicles deployment observability · local-only

This read-only collector polls three known GitHub Actions workflows: production
release train, API (staging/production), and Pages. It exposes bounded-cardinality
Prometheus gauges, deploy outcome/duration, last success, current runs, and
collector health. It **never triggers deployment** or needs OCI/Cloudflare secrets.

## Run on the mini-PC

From this directory:

```sh
docker compose up -d --build
curl -fsS http://127.0.0.1:9098/-/healthy
curl -fsS http://127.0.0.1:9098/api/v1/query?query=shadowops_exporter_up
```

Prometheus is **bound only to 127.0.0.1:9098**, and the exporter has no host port.
No inbound public connectivity or GitHub secrets are required: the repo is public
and the three 5-minute GitHub API polls use approximately 36 calls/hour (below
GitHub's usual unauthenticated 60/hour/IP limit). Other consumers of the same
public IP can exhaust that shared rate quota. For higher limits, set an optional
read-only fine-grained GitHub token as `GITHUB_TOKEN` in a local non-committed
`.env` file with permissions 0600 (never in GitHub Actions logs or dashboards).
It needs Actions **read**, not write. Do not expose the exporter to the Internet.

In an existing native Grafana add a Prometheus data source at
`http://127.0.0.1:9098`; if Grafana is in a different container, join a
private Docker network or configure `host.docker.internal:host-gateway` and
use `http://host.docker.internal:9098` **only after moving the Prometheus
host bind to a private/LAN-reachable interface**. The default loopback binding
does *not* allow access from other containers through the host gateway. Prefer a
shared private Docker network for Grafana and Prometheus.

Import `dashboard.json` into Grafana and choose that Prometheus data source.
Alerts are already defined as Prometheus rules; configure the intended
Alertmanager/Grafana notification routing separately.

## Interpretation and limits

- New read-only train dry-runs are marked in the workflow title and excluded;
  older manual dry-runs before that marker cannot be distinguished from a real
  manual train using only run-list metadata. For strict historical proof, inspect
  the train job and its archived receipt in GitHub Actions.
- The train metric represents the release-train *workflow* result, including API,
  Pages, receipts and public audit when its promotion job actually ran (never
  equate an API-green child with train-green).
- `last_run_id` is a GitHub Actions ID, **not** the Chronicles source SHA.
- Pages manual `workflow_dispatch` runs have no target in the existing run
  title and are labelled `environment="unspecified"`, never incorrectly
  attributed to production. The production train itself reliably reports
  production status, including its Pages promotion.
- The last-success timestamp comes from up to 100 recent workflow runs. A long
  history gap can mean *unknown* rather than a proven missing release.
- Github Actions data cannot prove the public game is live and functional;
  add separate HTTPS/game-journey synthetic probes for production SLIs.
- A failing GitHub poll keeps the last snapshot **but marks exporter_up=0**.
  Prometheus retention is 30 days or 1 GB, whichever limit is hit first.
- Healthz means the process responds, not that GitHub is healthy. Use
  `shadowops_exporter_up` for upstream health.
- Avoid forwarding deployment event bodies or credentials to public dashboards.

## Offline unit tests

```sh
python3 -m unittest discover -s tests -p test_chronicles_deploy_exporter.py -v
```
