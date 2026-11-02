import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import identity_staging_bundle as bundle
import identity_staging_provision as provision

class FootballConsumer(unittest.TestCase):
 def test_explicit_opt_in_is_idempotent_and_preserves_all_existing_private_material(self):
  original=bundle.generate('synthetic-tunnel-'+'a'*64)
  before=copy.deepcopy(original)
  configured=bundle.enable_football(original)
  self.assertEqual(original,before)
  self.assertEqual(set(configured['consumers']),{'chronicles','football'})
  self.assertNotEqual(configured['consumers']['football'],configured['consumers']['chronicles'])
  for key in bundle.KEYS-{'consumers'}:self.assertEqual(configured[key],original[key])
  self.assertEqual(configured['consumers']['chronicles'],original['consumers']['chronicles'])
  self.assertEqual(bundle.enable_football(configured),configured)
  self.assertNotIn('cka-simulator',configured['consumers'])
 def test_unknown_opt_in_is_refused_before_any_sdk_or_cloud_mutation(self):
  with self.assertRaises(provision.ProvisionError):
   provision.provision(None,{'IDENTITY_STAGING_FOOTBALL':'all'},None)

if __name__=='__main__':unittest.main()
