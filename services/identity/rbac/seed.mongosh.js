// Synthetic, ephemeral MongoDB 7 authorization test fixture. DO NOT load into a live DB.
// The root user is created by the disposable Docker container only.
"use strict";

const databaseName = "shadowops_identity_staging";
const staging = db.getSiblingDB(databaseName);
const adminJournal = "admin_suspension_journal";
const governanceJournal = "admin_signer_policy_events";
const signerPolicy = "admin_signer_policy";

for (const collection of [
  adminJournal, governanceJournal, signerPolicy, "pending_accounts", "sessions",
]) {
  assert.commandWorked(staging.runCommand({ create: collection }));
}
const at = (collection, actions) => ({
  resource: { db: databaseName, collection },
  actions,
});

assert.commandWorked(staging.runCommand({
  createRole: "identity_index_maintenance",
  privileges: [
    at(adminJournal, ["createIndex", "listIndexes"]),
    at(governanceJournal, ["createIndex", "listIndexes"]),
  ],
  roles: [],
}));
assert.commandWorked(staging.runCommand({
  createRole: "identity_signed_suspension",
  privileges: [
    at(adminJournal, ["insert", "listIndexes"]),
    at(signerPolicy, ["update"]),
    at("pending_accounts", ["update"]),
    at("sessions", ["remove"]),
  ],
  roles: [],
}));
assert.commandWorked(staging.runCommand({
  createUser: "identity_schema_maintainer",
  pwd: process.env.IDENTITY_RBAC_MAINT_PASS,
  roles: [{ role: "identity_index_maintenance", db: databaseName }],
}));
assert.commandWorked(staging.runCommand({
  createUser: "identity_suspension_executor",
  pwd: process.env.IDENTITY_RBAC_EXEC_PASS,
  roles: [{ role: "identity_signed_suspension", db: databaseName }],
}));
assert.commandWorked(staging.runCommand({
  insert: "pending_accounts",
  documents: [{
  _id: "11111111-1111-4111-8111-111111111111",
  environment: "staging",
  state: "active",
  credentials_disabled: false,
  session_version: NumberLong(1),
  }],
}));
assert.commandWorked(staging.runCommand({
  insert: "sessions",
  documents: [{
  _id: "fixture-session",
  environment: "staging",
  subject: "11111111-1111-4111-8111-111111111111",
  session_version: NumberLong(1),
  }],
}));
assert.commandWorked(staging.runCommand({
  insert: "admin_signer_policy",
  documents: [{
  _id: "staging:suspend-and-revoke",
  environment: "staging",
  state: "active",
  action: "suspend-and-revoke",
  generation: NumberLong(1),
  use_fence: NumberLong(0),
  }],
}));
print("synthetic roles and fixtures provisioned");
