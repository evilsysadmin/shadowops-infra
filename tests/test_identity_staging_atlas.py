import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas import AtlasConfigurationError, atlas_service_config

APP = 'mongodb+srv://runtime:fixture@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin&retryWrites=true&w=majority'
INVENTORY = 'mongodb+srv://inventory:fixture@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin'

class AtlasServiceConfigTests(unittest.TestCase):
    def test_separate_users_preserve_other_configuration_without_mutating_source(self):
        base = {'environment': 'staging', 'mongo_uri': 'local', 'mongo_ca_pem': 'private', 'consumers': {'chronicles': 'fixture'}, 'admin_inventory_access_history': True}
        before = copy.deepcopy(base)
        result = atlas_service_config(base, APP, INVENTORY)
        self.assertEqual(base, before)
        self.assertEqual(result['mongo_uri'], APP)
        self.assertEqual(result['admin_inventory_mongo_uri'], INVENTORY)
        self.assertEqual(result['mongo_ca_pem'], '')
        self.assertEqual(result['consumers'], base['consumers'])
        self.assertTrue(result['admin_inventory_access_history'])
        result['consumers']['chronicles'] = 'changed'
        self.assertEqual(base, before)

    def test_rejects_unsafe_endpoints_and_shared_user(self):
        base = {'environment': 'staging'}
        bad = [APP.replace('mongodb+srv', 'mongodb'), APP.replace('cluster.mongodb.net', 'attacker.example'), APP.replace('tls=true', 'tls=false'), APP.replace('tls=true', 'tls=true&tlsInsecure=true'), APP.replace('tls=true', 'tls=true&TLS=false'), APP.replace('shadowops_identity_staging', 'shadowops_identity_production'), APP.replace('authSource=admin', 'authSource=other'), APP.replace('runtime:fixture@', 'runtime@')]
        for uri in bad:
            with self.subTest(uri=uri), self.assertRaises(AtlasConfigurationError):
                atlas_service_config(base, uri, INVENTORY)
        for uri in (INVENTORY.replace('inventory:', 'runtime:'), INVENTORY.replace('inventory:', '%72untime:'), INVENTORY.replace('cluster.mongodb.net', 'other.mongodb.net')):
            with self.subTest(uri=uri), self.assertRaises(AtlasConfigurationError):
                atlas_service_config(base, APP, uri)
        with self.assertRaises(AtlasConfigurationError):
            atlas_service_config({'environment': 'production'}, APP, INVENTORY)
