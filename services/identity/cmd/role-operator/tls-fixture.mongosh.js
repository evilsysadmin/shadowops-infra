// Disposable local replica only. Never connect this fixture to staging.
const topology = db.adminCommand({hello: 1});
if (topology.setName !== 'identity-runtime-rs' || topology.hosts.length !== 1 || topology.hosts[0] !== '127.0.0.1:27019') throw new Error('non-local role fixture refused');
const auth = db.getSiblingDB('admin').auth('identity_root', process.env.RUNTIME_ROOT_PASS);
if (!(auth === true || auth === 1 || auth.ok === 1)) throw new Error('fixture authentication failed');
const stage = db.getSiblingDB('shadowops_identity_staging');
function worked(result) { if (!result.ok) throw new Error('fixture setup failed'); }
const at = (collection, actions) => ({resource:{db:stage.getName(),collection},actions});
worked(stage.createCollection('admin_role_change_journal'));
worked(stage.createCollection('admin_role_signer_policy'));
worked(stage.createRole({role:'role_test_schema', roles:[], privileges:[at('admin_role_change_journal',['createIndex','listIndexes'])]}));
worked(stage.createRole({role:'role_test_bootstrap', roles:[], privileges:[at('admin_role_change_journal',['insert','listIndexes']),at('admin_role_signer_policy',['insert'])]}));
worked(stage.createRole({role:'role_test_executor', roles:[], privileges:[at('admin_role_change_journal',['insert','listIndexes']),at('admin_role_signer_policy',['update']),at('pending_accounts',['update']),at('sessions',['remove']),at('staging_cka_tokens',['update'])]}));
worked(stage.createUser({user:'role_test_schema',pwd:process.env.ROLE_TEST_SCHEMA_PASS,roles:[{role:'role_test_schema',db:stage.getName()}]}));
worked(stage.createUser({user:'role_test_bootstrap',pwd:process.env.ROLE_TEST_BOOTSTRAP_PASS,roles:[{role:'role_test_bootstrap',db:stage.getName()}]}));
worked(stage.createUser({user:'role_test_executor',pwd:process.env.ROLE_TEST_EXECUTOR_PASS,roles:[{role:'role_test_executor',db:stage.getName()}]}));
print('DISPOSABLE_ROLE_FIXTURE_READY');
