# Staging account inventory: first read-only component

This package reads pages of native ShadowOps Identity staging accounts from the fixed `shadowops_identity_staging.pending_accounts` collection. It selects the subject, name, account state, credentials-disabled flag, creation time and session version. Stable UUID pagination is bounded to 50 accounts; legacy reservations are not native accounts and are excluded. It also counts unexpired session records matching the account's current version, only for active, enabled accounts. Session versions are not returned in JSON and session handles and digests are never selected.

The count is a point-in-time operational indication, not an authorization check: accounts and session records are read separately and may change concurrently. Session rotation changes the record's issuance time, so neither this count nor that timestamp is a login history, a device list or evidence of game activity. A separate read-only principal needs `find` on `pending_accounts` and `sessions` and must be provisioned independently of the public runtime.

This package is **not an admin interface or an authorization boundary**. It is not wired to HTTP, the browser, or the live runtime. A future caller must authenticate the operator, authorize platform administration server-side, audit access, restrict database privileges and handle errors before exposing this information. A game-specific admin role or browser-provided subject does not confer this authority. Deploying or granting database permissions is outside this change.

The current schema does not establish a reliable cross-game login history, current location, play history or game progress. No such fields are inferred from token issuance or invented here. Those require explicit, independently authorized product integrations and clear event semantics. Staging and production remain separate.

The Mongo integration test uses synthetic accounts in a dedicated disposable MongoDB at `127.0.0.1:27097`, enabled by `IDENTITY_INVENTORY_TEST_MONGO=mongodb://127.0.0.1:27097`. The CI Mongo workflow provides a separate fixture for this test. Do not point the test at a real database.
