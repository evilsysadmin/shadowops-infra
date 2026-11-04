import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_roles import payloads

class AtlasRoleTests(unittest.TestCase):
    def test_scoped_roles_have_no_wildcards_or_inherited_privileges(self):
        roles = payloads()
        self.assertEqual(len(roles), 4)
        self.assertEqual(len({r['roleName'] for r in roles}), 4)
        expected_collections = {'pending_accounts', 'sessions', 'staging_cka_tokens', 'staging_application_access_history', 'admin_inventory_audit'}
        seen = set()
        for role in roles:
            self.assertEqual(role['inheritedRoles'], [])
            for action in role['actions']:
                self.assertIn(action['action'], {'FIND', 'INSERT', 'UPDATE', 'REMOVE', 'CREATE_INDEX', 'LIST_INDEXES'})
                for resource in action['resources']:
                    self.assertEqual(resource['db'], 'shadowops_identity_staging')
                    self.assertIn(resource['collection'], expected_collections)
                    seen.add(resource['collection'])
        self.assertEqual(seen, expected_collections)
        backup = next(r for r in roles if r['roleName'].endswith('_backup'))
        self.assertEqual([a['action'] for a in backup['actions']], ['FIND'])
        self.assertEqual({r['collection'] for r in backup['actions'][0]['resources']}, expected_collections)
        restore = next(r for r in roles if r['roleName'].endswith('_restore'))
        actions = {a['action']: {r['collection'] for r in a['resources']} for a in restore['actions']}
        self.assertEqual(actions, {'FIND': expected_collections, 'INSERT': {'pending_accounts', 'admin_inventory_audit', 'staging_application_access_history'}})
