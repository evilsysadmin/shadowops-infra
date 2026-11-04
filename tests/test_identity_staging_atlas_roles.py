import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_roles import payloads

class AtlasRoleTests(unittest.TestCase):
    def test_scoped_roles_have_no_wildcards_or_inherited_privileges(self):
        roles = payloads()
        self.assertEqual(len(roles), 2)
        self.assertEqual(len({r['roleName'] for r in roles}), 2)
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
