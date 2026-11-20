# ShadowOps ID · cross-game guest exposure inventory

This is a **read-only detection control**, not a rollout or proof of working
ShadowOps ID. No Cloudflare/OCI/Identity credentials are used. Run
`python3 -m unittest discover -s tests -p test_game_identity_exposure.py -v`
and `python3 scripts/game_identity_exposure.py audit` from Infra.

The registry in `scripts/game_identity_exposure.py` covers all eight
dedicated game repositories: Chess Studio, Chronicles, Star Adventures, Tactics,
Football, Pawn Action, Snooker/Billiards and Matthias Bridge Squad. Tactics is
explicitly **unpublished** and its integrated mode remains owned by Chronicles.
The endpoint audit checks known custom staging/production game hosts, plus
predictable Pages project aliases. Opaque immutable Pages aliases are not
discoverable without Cloudflare's read-only inventory. CKA is a training
simulator with its own public retirement procedure, not a game.

**Strict guest contract:** canonical game root and /index.html must not
silently serve anonymous application content. Both GET and HEAD are checked.
Main pages.dev aliases must not serve the game either. HTTP 200/206 raises
REVIEW_ANONYMOUS_200. This **does not prove** playable gameplay was leaked:
an intentionally public login shell can also be HTTP 200, and requires
product-specific inspection. Redirects, network failure, 404 canonical hosts
and 503 holding shells do not demonstrate a working authenticated login.
No redirects are followed, credentials used, TLS checks weakened or writes
made; response bodies are never included in audit results.

The nightly/manual **Games · ShadowOps ID guest exposure audit** runs only on
trusted Infra main. PRs run offline contract tests, not network probes. An
audit failure is a triage signal, not permission to weaken the Identity gate.

## Remaining consumer work (tracked separately from this detection PR)

- **Star Adventures staging:** existing public static Pages publisher; no
  dedicated server-side Identity gate or staradvs audience yet. Requires
  registered audience, app-only service proof, edge gate, revised SHA-pinned
  release/rollback, and actual authenticated E2E before a protected release.
- **Pawn Action:** holding Worker and a candidate staging verifier exist,
  but holding status is not authenticated gameplay.
- **Bridge Squad production:** reviewed source-level gate requires an
  operational independent production issuer, audience and proof.
  A holding 401 alone does not prove successful login.
- **Football and Snooker staging:** app-specific gates exist; use the
  existing trusted operator workflows to verify real signed-in access,
  session expiry, logout/revocation and all dynamically assigned aliases.
- **Chess Studio and Chronicles:** verify frontend/API login boundaries,
  account-specific saves, signed issuer/audience, legacy SSO migration and
  live session freshness. A public landing page alone is not an API breach.
- **Tactics:** no separately playable frontend; needs its own registered
  audience and authoritative backend before publication.

Before saying **every game is protected**, verify current Cloudflare DNS,
Pages and immutable aliases, guest HTML/JS/API denials, each exact issuer and
audience, real account login, logout/revocation, cross-account isolation and
SHA-pinned live browser acceptance. This inventory deliberately claims none
of those user-session checks.
