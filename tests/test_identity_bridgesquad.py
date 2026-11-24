"""Bridge Squad ShadowOps ID (staging): staging-only, opt-in and no foreign credentials."""
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


class BridgeSquadConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = bundle.generate('synthetic-bridgesquad-tunnel-' + 'a' * 64)

    def test_explicit_enable_preserves_existing_custody_and_is_idempotent(self):
        before = copy.deepcopy(self.original)
        enabled = bundle.enable_bridgesquad(before)
        self.assertEqual(before, self.original)
        self.assertEqual(set(enabled['consumers']), {'chronicles', 'bridgesquad'})
        self.assertEqual(bundle.enable_bridgesquad(enabled), enabled)
        self.assertNotEqual(enabled['consumers']['bridgesquad'], before['consumers']['chronicles'])
        for key in bundle.KEYS - {'consumers'}:
            self.assertEqual(enabled[key], before[key], key)
        self.assertNotIn('bridgesquad', bundle.service_config(before)['consumers'])
        self.assertEqual(bundle.service_config(enabled)['consumers'], enabled['consumers'])

    def test_credential_is_independent_of_other_existing_game_proofs(self):
        previous = bundle.enable_staradvs(bundle.enable_snooker(
            bundle.enable_pawn_action(bundle.enable_football(copy.deepcopy(self.original)))))
        enabled = bundle.enable_bridgesquad(previous)
        self.assertEqual({k: v for k, v in enabled['consumers'].items() if k != 'bridgesquad'},
                         previous['consumers'])
        self.assertEqual(len(set(enabled['consumers'].values())), len(enabled['consumers']))
        self.assertEqual(bundle.enable_bridgesquad(enabled), enabled)
        self.assertEqual(bundle.enable_snooker(enabled), enabled)
        self.assertEqual(bundle.enable_staradvs(enabled), enabled)

    def test_unknown_reused_or_invalid_proof_is_rejected(self):
        good = bundle.enable_bridgesquad(copy.deepcopy(self.original))
        for changed in ({'bridgesquad': good['consumers']['chronicles']},
                        {'bridgesquad': 'invalid'},
                        {'foreign-app': 'soc1_' + 'a' * 43}):
            with self.subTest(changed=changed):
                bad = copy.deepcopy(good)
                bad['consumers'].update(changed)
                with self.assertRaises(bundle.BundleError):
                    bundle.validate(bad)

    def test_nonstaging_or_implicit_operator_optin_rejected_before_cloud(self):
        for mode in ('production', 'all', 'yes', 'True', ''):
            with self.subTest(mode=mode), self.assertRaises(provision.ProvisionError):
                provision.provision(None, {'IDENTITY_STAGING_BRIDGESQUAD': mode}, None)

    def test_default_off_and_explicit_enable_changes_only_bridgesquad_proof(self):
        original = copy.deepcopy(self.original)
        cf = SimpleNamespace(account='fixture',
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
                env = {} if mode == 'preserve' else {'IDENTITY_STAGING_BRIDGESQUAD': mode}
                provision.provision(SimpleNamespace(), env, cf)
                generate.assert_not_called()
                self.assertEqual(store.call_count, int(mode == 'enable'))
                if mode == 'enable':
                    saved = store.call_args.args[-1]
                    self.assertEqual(set(saved['consumers']), {'chronicles', 'bridgesquad'})
                    for key in bundle.KEYS - {'consumers'}:
                        self.assertEqual(saved[key], original[key])
                self.assertNotIn('bridgesquad', original['consumers'])


if __name__ == '__main__':
    unittest.main()
