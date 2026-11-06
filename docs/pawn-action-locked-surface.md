# Pawn Action · anonymous locked staging HTTPS probe

This is a **read-only, pre-activation** live perimeter test. It is distinct
from the Cloudflare account-level DNS/Pages/R2 inventory and from a playable
ShadowOps ID login test.

The canonical host is `https://staging.pawnaction.shadowops.dpdns.org/`.
Run from a workstation with ordinary HTTPS access:

```sh
python3 -m unittest discover -s tests -p 'test_pawn_action_staging_surface.py' -v
python3 scripts/pawn_action_staging_surface.py probe
```

Or manually dispatch **Pawn Action · locked staging HTTPS surface (read only)**
from `evilsysadmin/shadowops-infra` protected `main`, setting
`probe_live_locked=true`. The automatic PR/push jobs run **offline tests
only**; the manual live job has no Cloudflare or Identity secrets and makes
no writes.

The probe fails closed unless the real TLS endpoint returns the exact public
`/_shadowops/status` payload identifying Pawn Action staging as locked,
plus HTTP 403/404/503 denial of anonymous root and BOTH GET and HEAD
for game entry points, WASM, PCK and both new and legacy pointer paths.
Testing HEAD alone would miss a Worker that serves bytes on GET.
It rejects HTTP redirects, cacheable responses and missing `nosniff`.
The target list is constant, never user-supplied; it sends no cookies/tokens,
never follows redirects and reads no gameplay payloads (only a bounded
status JSON).

**A green offline test is not live evidence.** If DNS/Pages is absent, the
manual live probe should fail, not claim success. When an authenticated
private staging build is *intentionally* activated, the locked-state probe
should become red/obsolete; it must be replaced by separate anonymous-denial
and authenticated gameplay E2E gates, not weakened to accept public Web assets.

This workflow does not create the bucket, configure Pages/DNS, enable Identity,
publish an R2 release, advance the source `main`, or modify Chess Studio.
