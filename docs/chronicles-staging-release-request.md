# Reviewed Chronicles staging release request

Updated: 2026-10-20

This deliberately low-friction deployment request is a fallback when the
optional source-to-Infra Actions token has not been installed. A PR modifying
this file triggers the two **dedicated Infra release workflows** on protected
Infra `main` after merge:

- Chronicles frontend → isolated Cloudflare Pages project and HTTPS smoke
- Chronicles API → signed GHCR image → isolated OCI A1 → health/player E2E smoke

**Requested source at PR creation:** `e2912ce62f277f64ecb5408db41cd051df4caf81`.

The PR is **not authorization to deploy an unverified or stale SHA**. Each
publisher independently discovers the actual current protected Chronicles main
and requires all three source-main CI workflows to have succeeded for that exact
SHA. If main advances or checks are pending, the release skips and hourly
polling retries; production is never part of this request.

The frontend must publish `release.json` reporting its exact build SHA and
serve it on the public staging domain. The in-app "Nueva versión disponible"
notice offers an explicit refresh outside gameplay and never forces one during
an expedition.

This file is not a deployment receipt. Only successful Infra Pages/API jobs
with real public smoke markers and matching recorded artifacts prove a release.
