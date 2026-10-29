// Real MongoDB 7 authorization checks against a disposable auth-enabled replica set.
// Every connection below authenticates as a separate role: a root connection
// is used ONLY to inspect the outcome of the least-privilege transaction.
"use strict";

const stagingName = "shadowops_identity_staging";
const root = db.getSiblingDB(stagingName);
const suffix = `@127.0.0.1:27019/${stagingName}?authSource=${stagingName}&directConnection=true`;
function roleDB(name, password) {
  const uri = `mongodb://${encodeURIComponent(name)}:${encodeURIComponent(password)}${suffix}`;
  return new Mongo(uri);
}
function commandWorked(label, database, command) {
  const result = database.runCommand(command);
  assert.commandWorked(result, label);
  return result;
}
function denied(label, database, command) {
  try {
    const result = database.runCommand(command);
    if (result.ok === 0 && result.code === 13) {
      print("DENIED " + label);
      return;
    }
    throw new Error("overprivileged role: " + label + ", response: " + tojson(result));
  } catch (err) {
    if (err.code === 13 || err.codeName === "Unauthorized" ||
        /not authorized|Unauthorized/.test(String(err.message))) {
      print("DENIED " + label);
      return;
    }
    throw err;
  }
}
const maintenanceConn = roleDB("identity_schema_maintainer", process.env.IDENTITY_RBAC_MAINT_PASS);
const runtimeConn = roleDB("identity_suspension_executor", process.env.IDENTITY_RBAC_EXEC_PASS);
const maintenance = maintenanceConn.getDB(stagingName);
const runtime = runtimeConn.getDB(stagingName);
const adminJournal = "admin_suspension_journal";
const policyEvents = "admin_signer_policy_events";
const indexed = [
  { collection: adminJournal, name: "staging_action_nonce_unique" },
  { collection: policyEvents, name: "policy_retirement_nonce_unique" },
];

for (const spec of indexed) {
  commandWorked("schema maintenance creates unique indexes", maintenance, {
    createIndexes: spec.collection,
    indexes: [{
      key: { environment: 1, action: 1, nonce: 1 },
      name: spec.name,
      unique: true,
    }],
  });
  commandWorked("maintenance can inspect indexes", maintenance, { listIndexes: spec.collection });
}
denied("schema maintainer cannot insert audit", maintenance, {
  insert: adminJournal,
  documents: [{ _id: "bad-schema-write" }],
});
denied("schema maintainer cannot alter account", maintenance, {
  update: "pending_accounts",
  updates: [{ q: { _id: "11111111-1111-4111-8111-111111111111" }, u: { $set: { state: "disabled" } } }],
});
denied("schema maintainer cannot delete sessions", maintenance, {
  delete: "sessions", deletes: [{ q: {}, limit: 0 }],
});
denied("schema maintainer cannot alter audit", maintenance, {
  update: adminJournal, updates: [{ q: {}, u: { $set: { modified: true } } }],
});

for (const spec of indexed) {
  commandWorked("suspension can inspect preprovisioned audit index", runtime, {
    listIndexes: spec.collection === adminJournal ? adminJournal : adminJournal,
  });
  break;
}
denied("runtime cannot create an index", runtime, {
  createIndexes: adminJournal,
  indexes: [{ key: { unauthorized: 1 }, name: "unsafe_runtime_ddl" }],
});
denied("runtime cannot drop an index", runtime, {
  dropIndexes: adminJournal, index: "staging_action_nonce_unique",
});
denied("runtime cannot configure audit TTL", runtime, {
  collMod: adminJournal, index: { name: "staging_action_nonce_unique", expireAfterSeconds: 30 },
});
denied("runtime cannot update audit history", runtime, {
  update: adminJournal,
  updates: [{ q: {}, u: { $set: { tampered: true } }, multi: true }],
});
denied("runtime cannot delete audit history", runtime, {
  delete: adminJournal, deletes: [{ q: {}, limit: 0 }],
});
denied("runtime cannot drop audit history", runtime, { drop: adminJournal });
denied("runtime cannot read protected audit payloads", runtime, { find: adminJournal, filter: {} });
denied("runtime cannot insert governance events", runtime, {
  insert: policyEvents, documents: [{ _id: "forbidden-governance-event" }],
});
denied("runtime cannot create production data", runtime, {
  insert: "production_accounts", documents: [{ _id: "forbidden" }],
});

// Mirror the allowed Mongo commands for the real Go AuthorizedStagingRevoker.
// All four effects must commit atomically under the least-privilege identity.
const session = runtimeConn.startSession({ causalConsistency: false });
try {
  session.startTransaction({
    readConcern: { level: "snapshot" },
    writeConcern: { w: "majority" },
  });
  const txDB = session.getDatabase(stagingName);
  commandWorked("fence active signer policy", txDB, {
    update: "admin_signer_policy",
    updates: [{
      q: { _id: "staging:suspend-and-revoke", state: "active" },
      u: { $inc: { use_fence: NumberLong(1) } },
      multi: false,
    }],
  });
  commandWorked("suspend exact account", txDB, {
    update: "pending_accounts",
    updates: [{
      q: { _id: "11111111-1111-4111-8111-111111111111", session_version: NumberLong(1) },
      u: { $set: { state: "credential-staged-disabled", credentials_disabled: true },
           $inc: { session_version: NumberLong(1) } },
      multi: false,
    }],
  });
  commandWorked("remove revoked sessions", txDB, {
    delete: "sessions", deletes: [{
      q: { subject: "11111111-1111-4111-8111-111111111111", environment: "staging" },
      limit: 0,
    }],
  });
  commandWorked("append audit in same transaction", txDB, {
    insert: adminJournal,
    documents: [{
      _id: "staging:suspend-and-revoke:synthetic-rbac",
      environment: "staging",
      action: "suspend-and-revoke",
      nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      subject: "11111111-1111-4111-8111-111111111111",
    }],
  });
  session.commitTransaction();
} finally {
  session.endSession();
}

assert.eq(root.admin_suspension_journal.countDocuments({}), 1,
  "suspension audit not committed");
assert.eq(root.sessions.countDocuments({}), 0,
  "revoked session survived");
const updated = root.pending_accounts.findOne({
  _id: "11111111-1111-4111-8111-111111111111",
});
assert.eq(updated.state, "credential-staged-disabled", "account not disabled");
assert.eq(Number(updated.session_version), 2, "session version not fenced");
assert.eq(Number(root.admin_signer_policy.findOne({
  _id: "staging:suspend-and-revoke",
}).use_fence), 1, "signer policy write did not commit");
print("PASS authenticated MongoDB roles: narrow DDL + restricted transactional executor");
