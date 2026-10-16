# Staging receipt contract

A staging receipt must refer to the exact Chronicles SHA and immutable digest, successful health and smoke checks, and the source workflow run. Production promotion must match the receipt identity byte-for-byte.

This module validates **structure only**. It does not create trustworthy receipts, prove health tests actually ran, store tamper-evident records, or authorize production. A privileged staging deploy workflow must generate and sign or otherwise protect the receipt from its own verified results; production must retrieve it from trusted storage and recheck identity and freshness. Do not accept receipt JSON supplied by an untrusted caller.

No production deploy is enabled; Chess Studio untouched.


## Host-local receipt from the OCI A1 launcher

After the dedicated OCI staging service passes dependency readiness **and**
the two-synthetic-account read smoke, `scripts/oci_staging_deploy.py
--deploy-staging` atomically updates
`~/.local/state/chronicles-staging/last-verified-staging-receipt.json`
with the same fields validated by `createStagingReceipt`:
source repository/service, staging environment, full commit SHA, signed
multiarch image digest, publishing workflow run ID, both readiness/smoke
results, and UTC timestamp.

The file is private (mode `0600`) in a private state directory and is
written with a temporary file plus atomic replacement **only after smoke
succeeds**. `--check-only` never creates or retires it. When a new rollout
is about to mutate the live staging container, the previous current receipt
is atomically moved to `previous-verified-staging-receipt.json` as **historical
rollback evidence only**. If Compose fails to start or the smoke fails, there
is deliberately **no current verified receipt**. A failure during image pull
(before any change to the live service) leaves the prior current proof intact.
The history file must never be accepted as proof of *current* health. Both
rename operations are synchronized to the state directory. No JWT or database
URI is stored.

This is a **local operational record**, not a cryptographic signature or
proof the deployment actually ran in the current conversation. Promotion
must independently revalidate GitHub, the signed GHCR artifact, the live
staging endpoint and the approved ledger transitions before authorizing
production. The receipt is not uploaded to an external service by this PR.

**Safety boundary:** a receipt on disk is not a cryptographic attestation of
server state and cannot authorize promotion alone. Independent cloud inventory,
source attestation, live endpoint health and an immutable release ledger remain
necessary. If a process crashes during an upgrade, an absent current receipt
fails closed instead of incorrectly advertising the previous image as healthy.
