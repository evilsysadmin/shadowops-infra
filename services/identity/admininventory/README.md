# Staging account inventory: first read-only component

This package reads pages of native ShadowOps Identity staging accounts from the fixed `shadowops_identity_staging.pending_accounts` collection. It selects only the subject, name, account state, credentials-disabled flag and creation time. Stable UUID pagination is bounded to 50 accounts; legacy reservations are not native accounts and are excluded.

This package is **not an admin interface or an authorization boundary**. It is not wired to HTTP, the browser, or the live runtime. A future caller must authenticate the operator, authorize platform administration server-side, audit access, restrict database privileges and handle errors before exposing this information. A game-specific admin role or browser-provided subject does not confer this authority. Deploying or granting database permissions is outside this change.

The current schema does not establish a reliable cross-game login history, current location, play history or game progress. No such fields are inferred from token issuance or invented here. Those require explicit, independently authorized product integrations and clear event semantics. Staging and production remain separate.

The Mongo integration test uses synthetic accounts in a dedicated disposable MongoDB at `127.0.0.1:27097`, enabled by `IDENTITY_INVENTORY_TEST_MONGO=mongodb://127.0.0.1:27097`. The CI Mongo workflow provides a separate fixture for this test. Do not point the test at a real database.
