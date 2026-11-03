"""Staging-only opt-in for Pawn Action's independent ShadowOps ID audience."""
import copy
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import identity_staging_bundle as bundle
import identity_staging_provision as provision


class PawnActionConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=bundle.generate('synthetic-pawn-action-tunnel-'+'a'*64)

    def test_explicit_opt_in_preserves_all_existing_vault_values(self):
        original=copy.deepcopy(self.original)
        activated=bundle.enable_pawn_action(original)
        self.assertEqual(original,self.original, 'must not mutate current Vault config')
        self.assertEqual(set(activated['consumers']),{'chronicles','pawn-action'})
        for key in bundle.KEYS-{'consumers'}:
            self.assertEqual(activated[key],original[key],key)
        self.assertEqual(activated['consumers']['chronicles'],original['consumers']['chronicles'])
        self.assertNotEqual(activated['consumers']['pawn-action'],original['consumers']['chronicles'])
        self.assertNotEqual(activated['consumers']['pawn-action'][5:],original['signing_seed'])
        self.assertEqual(bundle.enable_pawn_action(activated),activated)
        self.assertNotIn('football',activated['consumers'])

    def test_optin_coexists_with_existing_football_and_is_independent(self):
        football=bundle.enable_football(copy.deepcopy(self.original))
        pawn=bundle.enable_pawn_action(football)
        self.assertEqual(set(pawn['consumers']),{'chronicles','football','pawn-action'})
        self.assertEqual({k:v for k,v in pawn['consumers'].items() if k!='pawn-action'},football['consumers'])
        self.assertEqual(bundle.enable_football(pawn),pawn)
        self.assertEqual(bundle.enable_pawn_action(pawn),pawn)
        cfg=bundle.service_config(pawn)
        self.assertEqual(cfg['consumers'],pawn['consumers'])
        self.assertNotIn('pawn-action',bundle.service_config(self.original)['consumers'])

    def test_unknown_consumer_and_reused_proof_rejected(self):
        good=bundle.enable_pawn_action(copy.deepcopy(self.original))
        for fault in ('unknown','duplicate','malformed'):
            changed=copy.deepcopy(good)
            if fault=='unknown':changed['consumers']['unapproved-app']='soc1_'+'x'*43
            elif fault=='duplicate':changed['consumers']['pawn-action']=changed['consumers']['chronicles']
            else:changed['consumers']['pawn-action']='football'
            with self.subTest(fault=fault),self.assertRaises(bundle.BundleError):
                bundle.validate(changed)

    def test_invalid_operator_opt_in_denied_before_cloud_sdk_usage(self):
        for input_value in ('all','yes','production','True','football'):
            with self.subTest(input_value=input_value),self.assertRaises(provision.ProvisionError):
                provision.provision(None,{'IDENTITY_STAGING_PAWN_ACTION':input_value},None)

    def test_default_provision_preserves_bundle_and_explicit_enable_stores_only_new_consumer(self):
        orig=copy.deepcopy(self.original)
        cf=SimpleNamespace(account='fixture',call=lambda method,path,*args:orig['tunnel_token'])
        for action in ('preserve','enable'):
            with self.subTest(action=action),patch.object(provision,'config_from_env',return_value={}),\
                 patch.object(provision,'resolve_existing_host',return_value=('compartment','instance')),\
                 patch.object(provision,'resolve_vault',return_value=('vault','key','compartment')),\
                 patch.object(provision,'load_existing',return_value=copy.deepcopy(orig)),\
                 patch.object(provision,'ensure_tunnel',return_value='fixture'),\
                 patch.object(provision,'dns_plan',return_value=('zone','target',True)),\
                 patch.object(provision,'store') as store,\
                 patch.object(provision,'generate') as generate:
                provision.provision(SimpleNamespace(),{'IDENTITY_STAGING_PAWN_ACTION':action},cf)
                generate.assert_not_called()
                self.assertEqual(store.call_count, int(action=='enable'))
                if action=='enable':
                    new=store.call_args.args[-1]
                    self.assertEqual(set(new['consumers']),{'chronicles','pawn-action'})
                    for key in bundle.KEYS-{'consumers'}:
                        self.assertEqual(new[key],orig[key])
                self.assertNotIn('pawn-action',orig['consumers'])

if __name__=='__main__':unittest.main()
