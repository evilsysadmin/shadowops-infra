// Disposable authenticated localhost fixture only; never an operational seed.
// mongosh does not expose the legacy shell's Mongo.host property. Inspect
// the actual single-node replica identity instead of a missing client field.
const fixtureTopology = db.adminCommand({ hello: 1 });
if (fixtureTopology.setName !== 'identity-runtime-rs' || !Array.isArray(fixtureTopology.hosts) || fixtureTopology.hosts.length !== 1 || fixtureTopology.hosts[0] !== '127.0.0.1:27019') throw new Error('non-local runtime fixture refused');
const auth = db.getSiblingDB('admin').auth('identity_root', process.env.RUNTIME_ROOT_PASS);
if (!(auth === true || auth === 1 || auth.ok === 1)) throw new Error('fixture root authentication failed');
const stage = db.getSiblingDB('shadowops_identity_staging');
stage.createRole({ role: 'identity_runtime', roles: [], privileges: [
  { resource: { db: stage.getName(), collection: 'pending_accounts' }, actions: ['find', 'insert', 'update', 'createIndex', 'listIndexes'] },
  { resource: { db: stage.getName(), collection: 'sessions' }, actions: ['find', 'insert', 'update', 'remove', 'createIndex', 'listIndexes'] },
  { resource: { db: stage.getName(), collection: 'staging_cka_tokens' }, actions: ['find', 'insert', 'update', 'createIndex', 'listIndexes'] },
] });
stage.createRole({ role: 'identity_incomplete', roles: [], privileges: [
  { resource: { db: stage.getName(), collection: 'pending_accounts' }, actions: ['find'] },
] });
stage.createUser({ user: 'identity_runtime', pwd: process.env.RUNTIME_APP_PASS, roles: [{ role: 'identity_runtime', db: stage.getName() }] });
stage.createUser({ user: 'identity_broad', pwd: process.env.RUNTIME_BROAD_PASS, roles: [{ role: 'readWrite', db: stage.getName() }] });
stage.createUser({ user: 'identity_incomplete', pwd: process.env.RUNTIME_INCOMPLETE_PASS, roles: [{ role: 'identity_incomplete', db: stage.getName() }] });
print('IDENTITY_RUNTIME_FIXTURE_USERS_READY');
