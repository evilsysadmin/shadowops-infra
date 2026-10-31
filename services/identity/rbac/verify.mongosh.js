// Real MongoDB 7 authorization checks against a disposable auth-enabled replica set.
// Every connection below authenticates as a separate role: a root connection
// is used ONLY to inspect the outcome of the least-privilege transaction.
"use strict";
function ensureWorked(result, label) {
  if (!result || result.ok !== 1) throw new Error(label + ": " + tojson(result));
}
function ensureEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

const stagingName = "shadowops_identity_staging";
const root = db.getSiblingDB(stagingName);
const suffix = `@127.0.0.1:27019/${stagingName}?authSource=${stagingName}&directConnection=true`;
function roleDB(name, password) {
  const uri = `mongodb://${encodeURIComponent(name)}:${encodeURIComponent(password)}${suffix}`;
  return new Mongo(uri);
}
function commandWorked(label, database, command) {
  const result = database.runCommand(command);
  ensureWorked(result, label);
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
const rolesConn = roleDB("identity_role_executor", process.env.IDENTITY_RBAC_ROLE_EXEC_PASS);
const maintenance = maintenanceConn.getDB(stagingName);
const runtime = runtimeConn.getDB(stagingName);
const roles = rolesConn.getDB(stagingName);
const adminJournal = "admin_suspension_journal";
const policyEvents = "admin_signer_policy_events";
const roleJournal = "admin_role_change_journal";
const indexed = [
  { collection: adminJournal, name: "staging_action_nonce_unique" },
  { collection: policyEvents, name: "policy_retirement_nonce_unique" },
  { collection: roleJournal, name: "staging_role_nonce_unique" },
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
denied("schema maintainer cannot write role-change audit", maintenance, {
  insert: roleJournal, documents: [{ _id: "forbidden-role-schema-write" }],
});
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

commandWorked("suspension can inspect preprovisioned audit index", runtime, {
  listIndexes: adminJournal,
});
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
denied("suspension executor cannot write role-change audit", runtime, {
  insert: roleJournal, documents: [{ _id: "forbidden-suspension-role-write" }],
});
denied("role executor cannot insert suspension audit", roles, {
  insert: adminJournal, documents: [{ _id: "forbidden-role-suspension-write" }],
});
denied("runtime cannot insert governance events", runtime, {
  insert: policyEvents, documents: [{ _id: "forbidden-governance-event" }],
});
denied("runtime cannot create production data", runtime, {
  insert: "production_accounts", documents: [{ _id: "forbidden" }],
});

// A role-change operator is distinct from the signed suspension executor.
// The schema owner can set the exact permanent nonce index, whereas the
// role executor can only inspect it and atomically append journal entries.
commandWorked("role executor lists pre-provisioned permanent index", roles, {
  listIndexes: roleJournal,
});
denied("role executor cannot make DDL", roles, {
  createIndexes: roleJournal,
  indexes: [{ key: { unauthorized: 1 }, name: "unapproved-role-index" }],
});
denied("role executor cannot drop indexes", roles, {
  dropIndexes: roleJournal, index: "staging_role_nonce_unique",
});
denied("role executor cannot set audit TTL", roles, {
  collMod: roleJournal, index: { name: "staging_role_nonce_unique", expireAfterSeconds: 30 },
});
denied("role executor cannot read audit history", roles, {
  find: roleJournal, filter: {},
});
denied("role executor cannot overwrite audit history", roles, {
  update: roleJournal, updates: [{ q: {}, u: { $set: { tampered: true } } }],
});
denied("role executor cannot delete audit history", roles, {
  delete: roleJournal, deletes: [{ q: {}, limit: 0 }],
});
denied("role executor cannot drop audit history", roles, {
  drop: roleJournal,
});
denied("role executor cannot update suspension signer policy", roles, {
  update: "admin_signer_policy", updates: [{ q: { _id: "staging:suspend-and-revoke" }, u: { $inc: { use_fence: 1 } } }],
});
denied("suspension executor cannot update role signer policy", runtime, {
  update: "admin_role_signer_policy", updates: [{ q: { _id: "staging:set-role" }, u: { $inc: { use_fence: 1 } } }],
});
denied("role executor cannot update governance events", roles, {
  update: policyEvents, updates: [{ q: {}, u: { $set: { compromised: true } } }],
});
denied("role executor cannot read player records", roles, {
  find: "pending_accounts", filter: {},
});
denied("role executor cannot create an account", roles, {
  insert: "pending_accounts", documents: [{ _id: "forbidden-new-user" }],
});
denied("role executor cannot create a session", roles, {
  insert: "sessions", documents: [{ _id: "forbidden-new-session" }],
});
denied("role executor cannot create an app token", roles, {
  insert: "staging_cka_tokens", documents: [{ _id: "forbidden-new-token" }],
});
denied("role executor cannot write production data", roles, {
  update: "production_accounts", updates: [{ q: {}, u: { $set: { role: "admin" } } }],
});

const roleSubject = "22222222-2222-4222-8222-222222222222";
const roleSession = rolesConn.startSession({ causalConsistency: false });
try {
  roleSession.startTransaction({
    readConcern: { level: "snapshot" },
    writeConcern: { w: "majority" },
  });
  const txDB = roleSession.getDatabase(stagingName);
  commandWorked("role change fences independent signer policy", txDB, {
    update: "admin_role_signer_policy",
    updates: [{
      q: { _id: "staging:set-role", state: "active", action: "set-role" },
      u: { $inc: { use_fence: NumberLong(1) } }, multi: false,
    }],
  });
  commandWorked("role change CAS only exact active user", txDB, {
    update: "pending_accounts",
    updates: [{
      q: { _id: roleSubject, environment: "staging", role: "user",
           session_version: NumberLong(3), credentials_disabled: false },
      u: { $set: { role: "admin" }, $inc: { session_version: NumberLong(1) } },
      multi: false,
    }],
  });
  commandWorked("role change revokes browser sessions", txDB, {
    delete: "sessions",
    deletes: [{ q: { subject: roleSubject, environment: "staging" }, limit: 0 }],
  });
  commandWorked("role change revokes application tokens", txDB, {
    update: "staging_cka_tokens",
    updates: [{
      q: { subject: roleSubject, active: true },
      u: { $set: { active: false } }, multi: true,
    }],
  });
  commandWorked("role change appends immutable audit in same transaction", txDB, {
    insert: roleJournal,
    documents: [{
      _id: "staging:set-role:synthetic-rbac",
      environment: "staging", action: "set-role", nonce: "dddddddddddddddddddddddddddddddd",
      subject: roleSubject, from: "user", to: "admin",
    }],
  });
  roleSession.commitTransaction();
} finally {
  roleSession.endSession();
}
ensureEqual(root.admin_role_change_journal.countDocuments({}), 1,
  "role change must append exactly one journal event");
ensureEqual(root.sessions.countDocuments({ subject: roleSubject }), 0,
  "role change left session live");
ensureEqual(root.staging_cka_tokens.countDocuments({ subject: roleSubject, active: true }), 0,
  "role change left application token live");
ensureEqual(root.staging_cka_tokens.countDocuments({ subject: roleSubject, active: false }), 1,
  "role change did not deactivate token");
const roleAccount = root.pending_accounts.findOne({ _id: roleSubject });
ensureEqual(roleAccount.role, "admin", "role change did not update exact account");
ensureEqual(Number(roleAccount.session_version), 4, "role change did not invalidate session version");
const unrelatedSuspensionSubject = root.pending_accounts.findOne({
  _id: "11111111-1111-4111-8111-111111111111",
});
ensureEqual(Number(unrelatedSuspensionSubject.session_version), 1,
  "role operator touched an unrelated account");
ensureEqual(Number(root.admin_role_signer_policy.findOne({
  _id: "staging:set-role",
}).use_fence), 1, "role policy fence was not committed");
ensureEqual(root.admin_suspension_journal.countDocuments({}), 0,
  "role operation unexpectedly wrote suspension history");

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

ensureEqual(root.admin_suspension_journal.countDocuments({}), 1,
  "suspension audit not committed");
ensureEqual(root.sessions.countDocuments({}), 0,
  "revoked session survived");
const updated = root.pending_accounts.findOne({
  _id: "11111111-1111-4111-8111-111111111111",
});
ensureEqual(updated.state, "credential-staged-disabled", "account not disabled");
ensureEqual(Number(updated.session_version), 2, "session version not fenced");
ensureEqual(Number(root.admin_signer_policy.findOne({
  _id: "staging:suspend-and-revoke",
}).use_fence), 1, "signer policy write did not commit");
print("PASS authenticated MongoDB roles: narrow DDL + restricted transactional executor");
