import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from identity_staging_atlas_custody import AtlasCustodyError, prepare_atlas_custody, derived_configs

BASE='mongodb+srv://{}:fixture-password-123456@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin'
APP,INVENTORY,BACKUP=(BASE.format(x) for x in ('appuser','inventoryuser','backupuser'))

class AtlasCustodyTests(unittest.TestCase):
 def test_create_preserve_and_derive_without_mutation(self):
  original={'environment':'staging','mongo_uri':'local','mongo_ca_pem':'private-ca','consumers':{'chronicles':'fixture'}}
  before=copy.deepcopy(original)
  custody=prepare_atlas_custody(None,APP,INVENTORY,BACKUP)
  self.assertEqual(prepare_atlas_custody(custody,APP,INVENTORY,BACKUP),custody)
  service,backup=derived_configs(custody,original)
  self.assertEqual(original,before)
  self.assertEqual(service['mongo_uri'],APP)
  self.assertEqual(service['admin_inventory_mongo_uri'],INVENTORY)
  self.assertEqual(service['mongo_ca_pem'],'')
  self.assertEqual(backup['host'],'cluster.mongodb.net')
  self.assertEqual(backup['username'],'backupuser')
  self.assertEqual(backup['backup_key'],custody['backup_key'])
  self.assertNotIn('application_uri',backup)
  self.assertNotIn('backup_key',service)
 def test_refuse_rotation_shared_users_or_other_cluster(self):
  custody=prepare_atlas_custody(None,APP,INVENTORY,BACKUP)
  for app,inventory,backup in [(APP,APP,BACKUP),(APP,INVENTORY,APP),(APP,INVENTORY,BACKUP.replace('backupuser','%61ppuser')),(APP,INVENTORY,BACKUP.replace('cluster.mongodb.net','other.mongodb.net'))]:
   with self.subTest(backup=backup),self.assertRaises(AtlasCustodyError):prepare_atlas_custody(None,app,inventory,backup)
  with self.assertRaises(AtlasCustodyError):prepare_atlas_custody(custody,APP,INVENTORY,BACKUP.replace('fixture-password','changed-password'))
  tampered={**custody,'backup_key':'invalid'}
  with self.assertRaises(AtlasCustodyError):derived_configs(tampered,{'environment':'staging'})
