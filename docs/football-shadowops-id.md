# Football staging behind ShadowOps ID

Football is an explicitly activated `football` consumer at
`https://staging.football.shadowops.dpdns.org`. Its only issuer is
`https://id-staging.shadowops.dpdns.org`. Production has no Football consumer.
The login page pins its return origin and passes no credential in the URL.

The Football Pages edge verifies Ed25519 JWT signatures, exact issuer/audience,
the two-minute lifetime and the native UUID. It then calls Identity's trusted
freshness RPC before serving protected HTML/assets or accepting a session.
Revocation and unavailable Identity deny access. The browser persists only a
host-only Secure/HttpOnly cookie for Football; the short exchange token stays in memory, and the independent `soc1_` service
proof stays in the edge secret binding. Native accounts grant access to this
staging game, without importing Chess profile data or administrator roles.
Device-local careers are keyed by the verified UUID; unclaimed earlier saves
remain available only through explicit export/import.

Activation order:

1. Install the reviewed updated fixed Identity bundle parser on the existing A1:
   `make identity-staging-bootstrap` from the operator workstation. This updates
   policy only, preserving the database, keys and running service.
2. Dispatch `identity-staging-operations.yml`, `action=provision`,
   `football_consumer=enable`. This idempotently adds only Football's new service
   proof to the existing Vault bundle. Other consumers and signing/account keys
   remain unchanged.
3. Deploy the exact protected-main Identity image after all normal signature,
   Mongo/TLS and four-audience isolation checks pass. Use the existing admitted
   `identity-staging-operations.yml` deploy action.
4. Football's dedicated source must publish the edge gate. Infra may deliver it
   in fail-closed mode before activation; absent service proof must never restore
   anonymous play. Infra installs only Football's proof as
   `SHADOWOPS_FOOTBALL_SERVICE_CREDENTIAL` in Pages, using its existing Vault
   custody. Never copy the full operator bundle to Pages or the game repository.
5. Verify anonymous denial, actual ShadowOps login, per-account career isolation,
   refresh and logout/revocation against the public staging. The retired CKA
   service and all production providers remain disabled or unchanged.

The game's source/art and public static distribution are not account data. A
downloaded open-source game cannot protect local computation; the web staging's
session and account-specific UI are enforced at the server edge.
