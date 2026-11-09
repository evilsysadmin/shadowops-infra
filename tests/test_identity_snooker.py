"""Snooker staging credential opt-in: idempotent, isolated, and default-off."""
import copy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import identity_staging_bundle as bundle
import identity_staging_provision as provision


class SnookerProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = bundle.generate('synthetic-snooker-tunnel-' + 'a' * 64)

    def test_explicit_enable_preserves_existing_bundle_and_is_idempotent(self):
        before = copy.deepcopy(self.original)
        enabled = bundle.enable_snooker(before)
        self.assertEqual(before, self.original)
        self.assertEqual(set(enabled['consumers']), {'chronicles', 'snooker'})
        self.assertEqual(bundle.enable_snooker(enabled), enabled)
        self.assertNotEqual(enabled['consumers']['snooker'], before['consumers']['chronicles'])
        for key in bundle.KEYS - {'consumers'}:
            self.assertEqual(enabled[key], before[key], key)
        self.assertEqual(enabled['consumers']['chronicles'], before['consumers']['chronicles'])
        self.assertNotIn('snooker', bundle.service_config(before)['consumers'])
        self.assertEqual(bundle.service_config(enabled)['consumers'], enabled['consumers'])

    def test_existing_apps_keep_separate_credentials_with_snooker_enabled(self):
        existing = bundle.enable_pawn_action(bundle.enable_football(copy.deepcopy(self.original)))
        enabled = bundle.enable_snooker(existing)
        self.assertEqual({k: v for k, v in enabled['consumers'].items() if k != 'snooker'},
                         existing['consumers'])
        self.assertEqual(len(set(enabled['consumers'].values())), len(enabled['consumers']))
        self.assertEqual(bundle.enable_football(enabled), enabled)
        self.assertEqual(bundle.enable_pawn_action(enabled), enabled)

    def test_invalid_consumer_secrets_and_foreign_apps_are_rejected(self):
        valid = bundle.enable_snooker(copy.deepcopy(self.original))
        for changes in ({'snooker': valid['consumers']['chronicles']},
                        {'snooker': 'invalid'},
                        {'not-authorized': 'soc1_' + 'x' * 43}):
            with self.subTest(changes=changes):
                invalid = copy.deepcopy(valid)
                invalid['consumers'].update(changes)
                with self.assertRaises(bundle.BundleError):
                    bundle.validate(invalid)

    def test_invalid_operator_input_fails_before_cloud_access(self):
        for mode in ('all', 'production', 'yes', 'football', ''):
            with self.subTest(mode=mode), self.assertRaises(provision.ProvisionError):
                provision.provision(None, {'IDENTITY_STAGING_SNOOKER': mode}, None)

    def test_default_preserves_existing_vault_and_enable_writes_once(self):
        original = copy.deepcopy(self.original)
        cloud = SimpleNamespace(account='fixture',
                                call=lambda method, path, *args: original['tunnel_token'])
        for mode in ('preserve', 'enable'):
            with self.subTest(mode=mode), \
                 patch.object(provision, 'config_from_env', return_value={}), \
                 patch.object(provision, 'resolve_existing_host', return_value=('compartment', 'instance')), \
                 patch.object(provision, 'resolve_vault', return_value=('vault', 'key', 'compartment')), \
                 patch.object(provision, 'load_existing', return_value=copy.deepcopy(original)), \
                 patch.object(provision, 'ensure_tunnel', return_value='fixture'), \
                 patch.object(provision, 'dns_plan', return_value=('zone', 'target', True)), \
                 patch.object(provision, 'store') as store, \
                 patch.object(provision, 'generate') as generate:
                provision.provision(SimpleNamespace(), {'IDENTITY_STAGING_SNOOKER': mode}, cloud)
                generate.assert_not_called()
                self.assertEqual(store.call_count, int(mode == 'enable'))
                if mode == 'enable':
                    stored = store.call_args.args[-1]
                    self.assertEqual(set(stored['consumers']), {'chronicles', 'snooker'})
                    for field in bundle.KEYS - {'consumers'}:
                        self.assertEqual(stored[field], original[field], field)
                    self.assertEqual(stored['consumers']['chronicles'], original['consumers']['chronicles'])

    def test_second_explicit_enable_does_not_replace_existing_snooker_proof(self):
        previous = bundle.enable_snooker(copy.deepcopy(self.original))
        cloud = SimpleNamespace(account='fixture',
                                call=lambda method, path, *args: previous['tunnel_token'])
        with patch.object(provision, 'config_from_env', return_value={}), \
             patch.object(provision, 'resolve_existing_host', return_value=('compartment', 'instance')), \
             patch.object(provision, 'resolve_vault', return_value=('vault', 'key', 'compartment')), \
             patch.object(provision, 'load_existing', return_value=copy.deepcopy(previous)), \
             patch.object(provision, 'ensure_tunnel', return_value='fixture'), \
             patch.object(provision, 'dns_plan', return_value=('zone', 'target', True)), \
             patch.object(provision, 'store') as store:
            provision.provision(SimpleNamespace(), {'IDENTITY_STAGING_SNOOKER': 'enable'}, cloud)
            store.assert_not_called()
