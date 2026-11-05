import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('atlas_deploy', ROOT / 'host/identity-atlas-staging-deploy.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeployTests(unittest.TestCase):
 def test_backup_failure_prevents_container_operations(self):
  class Preflight:
   def trusted_paths(self):pass
   def execute(self,*args):self.fail('preflight must not run')
  class Backup:
   def private_config(self):return {}
  calls=[]
  with patch.object(deploy,'require_root_file'),patch.object(deploy,'require_recent_atlas_backup',side_effect=ValueError('backup')):
   with self.assertRaises(ValueError):deploy.update('sha256:'+'a'*64,'b'*40,runner=lambda *a,**k:calls.append(a),preflight=Preflight(),backup_operator=Backup())
  self.assertEqual(calls,[])

 def test_update_stays_on_atlas_and_rolls_back_when_verification_fails(self):
  old='sha256:'+'a'*64; new='sha256:'+'b'*64; sha='c'*40; identifier='d'*64
  for fail_candidate in (False,True):
   with self.subTest(fail_candidate=fail_candidate), tempfile.TemporaryDirectory() as temp:
    root=Path(temp); (root/'atlas-active').touch(mode=0o600); (root/'atlas-compose.yaml').touch(mode=0o600)
    calls=[]; active=[old]
    def runner(args,*,digest=None,timeout=180):
     calls.append((args,digest))
     if args[:3]==['docker','ps','-aq'] or args[:3]==['docker','ps','-q']:return identifier
     if args[:2]==['docker','inspect']:
      return json.dumps([{'Config':{'Image':'ghcr.io/evilsysadmin/shadowops-identity@'+active[0],'Labels':{'com.docker.compose.project':'shadowops-identity-staging','com.docker.compose.service':'identity'}},'State':{'Status':'running','Health':{'Status':'healthy'}},'HostConfig':{'PortBindings':None},'Mounts':[{'Destination':'/run/secrets/identity-staging.json','Source':'/etc/shadowops/identity-staging/atlas-service.json','RW':False}]}])
     if 'config' in args:return '{}'
     if 'up' in args:active[0]=digest;return ''
     if args[0]=='curl' and fail_candidate and active[0]==new:raise deploy.DeployError('unavailable')
     return ''
    class Preflight:
     def trusted_paths(self):pass
     def execute(self,digest,source):self.result=(digest,source)
    class Backup:
     def private_config(self):return {}
    from identity_staging_atlas_transition import TransitionCheckpoint,TransitionError
    preflight=Preflight();checkpoint=TransitionCheckpoint(root,expected_uid=os.getuid())
    with patch.object(deploy,'ROOT',root),patch.object(deploy,'STATE',root),patch.object(deploy,'require_root_file'),patch.object(deploy,'require_recent_atlas_backup'),patch.object(deploy,'verify_shared_a1_containers'),patch.object(deploy,'validate_atlas_compose'):
     if fail_candidate:
      with self.assertRaises(TransitionError):deploy.update(new,sha,runner=runner,preflight=preflight,backup_operator=Backup(),checkpoint=checkpoint)
      self.assertEqual(active[0],old)
     else:
      self.assertIn('IDENTITY_ATLAS_DEPLOY_OK',deploy.update(new,sha,runner=runner,preflight=preflight,backup_operator=Backup(),checkpoint=checkpoint))
      self.assertEqual(active[0],new)
    self.assertEqual(preflight.result,(new,sha)); self.assertFalse(checkpoint.path.exists())
    changes=[args for args,digest in calls if 'up' in args]
    self.assertTrue(changes)
    for command in changes:
     self.assertEqual(command[-1],'identity');self.assertIn('--no-deps',command);self.assertNotIn('--remove-orphans',command)
