import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_roles_check import roles_valid, check, DATABASE


def status(role='readWrite', db=DATABASE):
    return {'authInfo': {'authenticatedUsers': [{'user': 'fixture', 'db': 'admin'}],
            'authenticatedUserRoles': [{'role': role, 'db': db}],
            'authenticatedUserPrivileges': [{'resource': {'db': db, 'collection': ''}, 'actions': ['find']}]}}


class AtlasRoleCheckTests(unittest.TestCase):
    def test_database_scoped_roles_only(self):
        self.assertTrue(roles_valid(status(), 'readWrite'))
        self.assertTrue(roles_valid(status('read'), 'read'))
        self.assertFalse(roles_valid(status('readWriteAnyDatabase', 'admin'), 'readWrite'))
        self.assertFalse(roles_valid(status('readWrite'), 'read'))
        extra = status()
        extra['authInfo']['authenticatedUserPrivileges'].append({'resource': {'cluster': True}})
        self.assertFalse(roles_valid(extra, 'readWrite'))

    @patch('identity_staging_atlas_roles_check.validate_inputs', side_effect=ValueError('secret'))
    def test_bad_input_fails_without_connecting(self, _):
        self.assertEqual(check({}), 1)

    @patch('identity_staging_atlas_roles_check.validate_inputs', return_value=('app', 'inventory', 'backup'))
    def test_checks_each_account_and_rejects_wrong_backup_role(self, _):
        from unittest.mock import MagicMock
        from types import SimpleNamespace
        clients = []
        for role in ('readWrite', 'readWrite', 'readWrite'):
            client = MagicMock()
            client.__enter__.return_value = client
            client.admin.command.side_effect = [status(role), {'isWritablePrimary': True}]
            clients.append(client)
        factory = MagicMock(side_effect=clients)
        with patch.dict(sys.modules, {'pymongo': SimpleNamespace(MongoClient=factory)}):
            self.assertEqual(check({}), 1)
            self.assertEqual(factory.call_count, 3)
            for client in clients:
                client.admin.command.assert_any_call('connectionStatus', showPrivileges=True)
