# Snooker staging: isolated Atlas release, without altering legacy rollback

This is a **reviewed code path only**, not a request to deploy or an
assertion that Identity/Pages/DNS is live. Parent: issue #527.

The existing Atlas Identity image at source SHA
`34d5aa2f4db3f522336a150266ac21f94d3ce95f` does not support
`snooker`. Adding Snooker to the currently mounted
`atlas-service.json` would therefore destroy the safe rollback target.

## Fixed per-image configuration

The installed Atlas Compose template defaults to the unchanged
`/etc/shadowops/identity-staging/atlas-service.json`. Only the
root-owned Atlas release operator can explicitly select the separately
staged `atlas-snooker-service.json` for the candidate image. The
previous image is always recreated with the original config on rollback.

The operator refuses a missing, symlinked, wrongly owned or wrongly
permissioned Snooker candidate. It validates that the staged document
differs from the original local/Atlas configuration **only by the Snooker
consumer**. Candidate preflight mounts that isolated configuration
read-only; both rendered Compose configurations and both runtime bind
sources are checked against fixed allowlists. A failed candidate's
rollback must prove the original source SHA and original config mount
before removing the transition journal. Failure retains the journal.

The release handoff independently hashes the newly installed Snooker
policy/helper, preflight and exact Atlas Compose template. No arbitrary
config path, env file, image tag, Vault material or secret can be provided
from the client.

## Actual protected activation sequence (NOT performed by this PR)

1. The staging operator reviews protected Infra main and installs its
   exact admitted root wrappers once via the existing trusted SSH
   bootstrap. A GitHub merge does not update the live host.
2. Deliberately run the protected **ShadowOps Identity · isolated
   staging operational handoff** workflow with
   `action=provision` and `snooker_consumer=enable`. Confirm
   success without exposing the isolated Vault service proof.
3. Run the separate protected `action=atlas-snooker-config`, and
   require its exact `IDENTITY_ATLAS_SNOOKER_CONFIG_STAGED` receipt.
   **Do not use the old mounted configuration as a shortcut.**
4. Reconfirm current signed Identity candidate image, Atlas backup
   and verified quarantine restore, exact previous live SHA and healthy
   isolated host; only then use the existing reviewed Atlas-only SSH
   release path. Require a successful new public Identity release SHA
   and exact Snooker login callback. On any failure, stop and inspect
   the bounded rollback receipt; do not blindly retry.
5. After Identity is genuinely live and independent Snooker service
   proof is available, use the protected `snooker-pages-release.yml`
   workflow to publish the current **green source SHA and immutable
   build ZIP**. Verify fail-closed production/preview Pages aliases
   before custom DNS, then anonymous, wrong-audience, revoked,
   Identity-down and authenticated desktop/mobile WebGL behavior.

No action in this PR changes OCI, Cloudflare, Vault, DNS, Identity
runtime, other ShadowOps applications or the live Pages project.
