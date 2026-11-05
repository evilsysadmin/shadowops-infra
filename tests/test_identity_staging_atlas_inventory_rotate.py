import base64
import copy
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import identity_staging_atlas_inventory_rotate as rotate
from identity_staging_atlas_custody import AtlasCustodyError, prepare_atlas_custody

BASE = 'mongodb+srv://{}:synthetic-password-12345@cluster.mongodb.net/shadowops_identity_staging?authSource=admin&tls=true'
ENV = {'IDENTITY_ATLAS_STAGING_RUNTIME_URI': BASE.format('app'),
       'IDENTITY_ATLAS_STAGING_INVENTORY_URI': BASE.format('inventory').replace('synthetic-password', 'rotated-password'),
       'IDENTITY_ATLAS_STAGING_BACKUP_URI': BASE.format('backup')}
OLD = (ENV['IDENTITY_ATLAS_STAGING_RUNTIME_URI'], ENV['IDENTITY_ATLAS_STAGING_INVENTORY_URI'].replace('rotated-password', 'synthetic-password'), ENV['IDENTITY_ATLAS_STAGING_BACKUP_URI'])


class Model:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class InventoryRotationTests(unittest.TestCase):
    def fixture(self, existing):
        writes = []
        client = SimpleNamespace(list_secrets=object(), get_secret=lambda _: SimpleNamespace(headers={'etag': 'revision-1'}, data=SimpleNamespace(lifecycle_state='ACTIVE')),
            update_secret=lambda secret_id, request, **kwargs: writes.append((secret_id, request, kwargs)))
        sdk = SimpleNamespace(vault=SimpleNamespace(VaultsClient=lambda _: client,
              models=SimpleNamespace(Base64SecretContentDetails=Model, UpdateSecretDetails=Model)),
              pagination=SimpleNamespace(list_call_get_all_results=lambda *a, **k: SimpleNamespace(data=[SimpleNamespace(id='atlas-secret', lifecycle_state='ACTIVE')])))
        return sdk, writes

    def test_only_inventory_rotated_with_optimistic_concurrency(self):
        original = prepare_atlas_custody(None, *OLD)
        expected = copy.deepcopy(original)
        expected['inventory_uri'] = ENV['IDENTITY_ATLAS_STAGING_INVENTORY_URI']
        sdk, writes = self.fixture(original)
        with patch.object(rotate, 'config_from_env', return_value={}), patch.object(rotate, 'resolve_existing_host', return_value=('compartment', 'instance')), patch.object(rotate, 'resolve_vault', return_value=('vault', 'key', 'compartment')), patch.object(rotate, 'existing_secret', side_effect=[original, expected]), patch.object(rotate, 'execute_atlas_prepare') as guard:
            self.assertEqual(rotate.rotate(sdk, ENV, pause=lambda _: None), 'IDENTITY_ATLAS_INVENTORY_CUSTODY_ROTATED')
        guard.assert_called_once_with(sdk, {}, mode='check-inventory-inactive')
        self.assertEqual(len(writes), 1)
        secret_id, request, options = writes[0]
        self.assertEqual(secret_id, 'atlas-secret')
        self.assertEqual(options['if_match'], 'revision-1')
        stored = json.loads(base64.b64decode(request.secret_content.content))
        self.assertEqual(stored, expected)
        self.assertEqual(stored['backup_key'], original['backup_key'])

    def test_failed_inactive_check_cannot_rotate(self):
        original = prepare_atlas_custody(None, *OLD)
        sdk, writes = self.fixture(original)
        with patch.object(rotate, 'config_from_env', return_value={}), patch.object(rotate, 'resolve_existing_host', return_value=('compartment', 'instance')), patch.object(rotate, 'resolve_vault', return_value=('vault', 'key', 'compartment')), patch.object(rotate, 'existing_secret', return_value=original), patch.object(rotate, 'execute_atlas_prepare', side_effect=RuntimeError('blocked')):
            with self.assertRaises(RuntimeError):
                rotate.rotate(sdk, ENV, pause=lambda _: None)
        self.assertEqual(writes, [])

    def test_unchanged_inventory_never_updates_vault(self):
        current = prepare_atlas_custody(None, *ENV.values())
        sdk, writes = self.fixture(current)
        with patch.object(rotate, 'config_from_env', return_value={}), patch.object(rotate, 'resolve_existing_host', return_value=('compartment', 'instance')), patch.object(rotate, 'resolve_vault', return_value=('vault', 'key', 'compartment')), patch.object(rotate, 'existing_secret', return_value=current):
            self.assertEqual(rotate.rotate(sdk, ENV, pause=lambda _: None), 'IDENTITY_ATLAS_INVENTORY_CUSTODY_UNCHANGED')
        self.assertEqual(writes, [])

    def test_bad_input_never_contacts_oci(self):
        with patch.object(rotate, 'config_from_env') as config:
            with self.assertRaises(AtlasCustodyError):
                rotate.rotate(SimpleNamespace(), {}, pause=lambda _: None)
            config.assert_not_called()

    def test_no_update_for_other_credential_or_missing_custody(self):
        original = prepare_atlas_custody(None, *OLD)
        sdk, writes = self.fixture(original)
        wrong = dict(ENV, IDENTITY_ATLAS_STAGING_BACKUP_URI=BASE.format('backup').replace('synthetic-password', 'changed-password'))
        with patch.object(rotate, 'config_from_env', return_value={}), patch.object(rotate, 'resolve_existing_host', return_value=('compartment', 'instance')), patch.object(rotate, 'resolve_vault', return_value=('vault', 'key', 'compartment')), patch.object(rotate, 'existing_secret', return_value=original):
            with self.assertRaises(AtlasCustodyError):
                rotate.rotate(sdk, wrong, pause=lambda _: None)
        self.assertEqual(writes, [])
