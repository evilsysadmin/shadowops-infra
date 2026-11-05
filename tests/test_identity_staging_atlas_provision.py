import base64
import copy
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_atlas_provision as provision
from identity_staging_atlas_custody import AtlasCustodyError, prepare_atlas_custody

BASE='mongodb+srv://{}:synthetic-password-12345@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin'
ENV={'IDENTITY_ATLAS_STAGING_RUNTIME_URI':BASE.format('app'), 'IDENTITY_ATLAS_STAGING_INVENTORY_URI':BASE.format('inventory'), 'IDENTITY_ATLAS_STAGING_BACKUP_URI':BASE.format('backup')}

class AtlasProvisionTests(unittest.TestCase):
 def test_create_once_preserve_and_refuse_rotation(self):
  existing=prepare_atlas_custody(None,*ENV.values())
  with patch.object(provision,'config_from_env',return_value={}),patch.object(provision,'resolve_existing_host',return_value=('compartment','instance')),patch.object(provision,'resolve_vault',return_value=('vault','key','compartment')),patch.object(provision,'existing_secret',return_value=None),patch.object(provision,'store_new') as store:
   self.assertEqual(provision.provision(SimpleNamespace(),ENV),'IDENTITY_ATLAS_CUSTODY_CREATED')
   self.assertEqual(store.call_count,1)
  with patch.object(provision,'config_from_env',return_value={}),patch.object(provision,'resolve_existing_host',return_value=('compartment','instance')),patch.object(provision,'resolve_vault',return_value=('vault','key','compartment')),patch.object(provision,'existing_secret',return_value=copy.deepcopy(existing)),patch.object(provision,'store_new') as store:
   self.assertEqual(provision.provision(SimpleNamespace(),ENV),'IDENTITY_ATLAS_CUSTODY_PRESERVED')
   changed={**ENV,'IDENTITY_ATLAS_STAGING_BACKUP_URI':BASE.format('otherbackup')}
   with self.assertRaises(AtlasCustodyError):provision.provision(SimpleNamespace(),changed)
   store.assert_not_called()
 def test_unsafe_input_never_reaches_cloud(self):
  with patch.object(provision,'config_from_env') as config:
   with self.assertRaises(AtlasCustodyError):provision.provision(SimpleNamespace(),{})
   config.assert_not_called()
 def test_unavailable_existing_custody_never_becomes_a_new_secret(self):
  class Broken(Exception):pass
  sdk=SimpleNamespace(pagination=SimpleNamespace(list_call_get_all_results=lambda *a,**k:SimpleNamespace(data=[SimpleNamespace(lifecycle_state='ACTIVE')])),vault=SimpleNamespace(VaultsClient=lambda c:SimpleNamespace(list_secrets=None)),secrets=SimpleNamespace(SecretsClient=lambda c:SimpleNamespace(get_secret_bundle_by_name=lambda **k:(_ for _ in ()).throw(Broken()))))
  with self.assertRaises(AtlasCustodyError):provision.existing_secret(sdk,{},'vault','compartment')

 def test_store_only_creates_the_dedicated_atlas_secret(self):
  created=[]
  class Model:
   def __init__(self, **kwargs):self.__dict__.update(kwargs)
  operations=SimpleNamespace(create_secret_and_wait_for_state=lambda request,**kwargs:created.append(request))
  vault=SimpleNamespace(VaultsClient=lambda config:object(), VaultsClientCompositeOperations=lambda client:operations,
     models=SimpleNamespace(Base64SecretContentDetails=Model,CreateSecretDetails=Model))
  custody=prepare_atlas_custody(None,*ENV.values())
  provision.store_new(SimpleNamespace(vault=vault),{},'compartment','vault','key',custody)
  self.assertEqual(len(created),1)
  self.assertEqual(created[0].secret_name,'identity-staging-atlas-custody')
  stored=json.loads(base64.b64decode(created[0].secret_content.content))
  self.assertEqual(stored,custody)
  self.assertNotIn('mongo_root_password',stored)

class AtlasInputDiagnosticsTests(unittest.TestCase):
 def test_reports_only_fixed_categories_without_secrets(self):
  app,inventory,backup=ENV.values()
  cases=[((app.replace('/shadowops_identity_staging','/wrong'),inventory,backup),'runtime_uri_format'),((app,inventory.replace('tls=true','tls=false'),backup),'inventory_uri_format'),((app,inventory,backup.replace('authSource=admin','authSource=wrong')),'backup_uri_format'),((app,inventory,backup.replace('cluster.mongodb.net','different.mongodb.net')),'cluster_mismatch'),((app,inventory,app),'users_not_distinct'),((app,inventory,backup.replace('synthetic-password-12345','short')),'backup_credential_format')]
  for values,expected in cases:
   with self.subTest(reason=expected),self.assertRaises(provision.AtlasInputError) as error:provision.validate_inputs(*values)
   self.assertEqual(error.exception.code,expected)
   self.assertNotIn('synthetic-password',str(error.exception))
  with self.assertRaises(provision.AtlasInputError) as error:provision.validate_inputs('', '', backup)
  self.assertEqual(error.exception.code,'runtime_uri_format,inventory_uri_format')
  provision.validate_inputs(app,inventory,backup)
