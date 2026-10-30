# Trusted staging freshness transport

`NewStagingServiceHandler(ctx, issuer, signingSeed, ConsumerCredentials)` adds
`POST /api/identity/freshness` to the central browser handler. It is not used by
the default bootstrap and does not deploy a listener. Consumers must verify JWT
signature, fixed issuer/audience, times, UUID, sv and jti **before** requesting
freshness. This endpoint returns current evidence; it does not verify a JWT or
grant product/admin/laboratory permissions.

The trusted caller configuration maps each supported application to an
independently generated 256-bit credential (`soc1_` plus canonical base64url of
32 random bytes). At least one application must be configured. Unknown apps,
malformed credentials or the same credential shared across apps are rejected
at construction. Only domain-separated credential digests remain in the handler.
Provision them through separate per-environment/per-application server secret
stores; never put them in Vite/browser configuration, URLs, logs or Git. Each
consumer needs only its own credential, public JWKS and HTTPS endpoint, never
Identity Mongo credentials or the signing key. Rotation/revocation replaces the
explicit server configuration; there is no automatic default or cross-app key.

Request over validated TLS to `https://id-staging.shadowops.dpdns.org`:

```
Authorization: Bearer <that application's soc1_ credential>
Content-Type: application/json

{"subject":"<verified UUID>","session_version":1,"token_jti":"<verified jti>"}
```

No Origin, Cookie, query, caller-selected audience, issuer, timestamp or state
flags are accepted. This is a backend RPC: browser CORS/preflight is not enabled,
and a user JWT/password/session handle is not a service credential. The fixed
authenticated caller determines the audience-specific authority. Body size,
socket-peer/global request limits, and the authority's two-second deadline apply.
Forwarded IP/TLS/host assertions are ignored.

200 returns the existing eight evidence fields **plus `audience`**, all bound
to the exact verified JWT and fixed consumer. The CKA internal eight-field
adapter stays unchanged; a future HTTP adapter must verify the audience before
projecting that shape. Invalid credentials/bindings or revoked sessions return
401; storage unavailability returns 503. No state response is cached, and no
failure returns active evidence or changes a browser cookie. Consumers must
reject missing/mismatched/stale evidence and retry the authority for every
protected operation; evidence is not a reusable authorization lease.

Real TLS/Mongo integration checks the 3×3 caller/token audience matrix, central
logout despite still-cryptographically-valid JWTs, wrong session version,
browser/user credential rejection, request injection, duplicate authorization,
wrong environment host, unavailable Mongo and invalid/shared configuration.
This establishes the transport contract, not a deployed service or a completed
Chronicles/Chess/CKA integration. Runtime secrets, consumer adapters and actual
staging release/rollback remain required.
