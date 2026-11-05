import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_transition import current_atlas_image, TransitionError, TransitionCheckpoint, transition, IMAGE, CONFIG, TARGET, PROJECT


class AtlasTransitionTests(unittest.TestCase):
 def fixture(self):
  return {'Config':{'Image':IMAGE+'sha256:'+'a'*64,'Labels':{'com.docker.compose.project':PROJECT,'com.docker.compose.service':'identity'}},'State':{'Status':'running','Health':{'Status':'healthy'}},'HostConfig':{'PortBindings':None},'Mounts':[{'Source':CONFIG,'Destination':TARGET,'RW':False}]}

 def test_finds_rollback_digest_only_for_healthy_atlas_service(self):
  row=self.fixture()
  self.assertEqual(current_atlas_image([row]),'sha256:'+'a'*64)
  variants=[]
  for path,value in [(('Config','Image'),IMAGE+'latest'),(('State','Status'),'exited'),(('State','Health','Status'),'unhealthy'),(('HostConfig','PortBindings'),{'9443/tcp':[{'HostPort':'9443'}]}), (('Mounts',0,'Source'),'/etc/shadowops/identity-staging/service.json'),(('Mounts',0,'RW'),True), (('Config','Labels','com.docker.compose.project'),'other')]:
   changed=copy.deepcopy(row); target=changed
   for key in path[:-1]:target=target[key]
   target[path[-1]]=value;variants.append(changed)
  for changed in variants:
   with self.subTest(changed=changed),self.assertRaises(TransitionError):current_atlas_image([changed])
  for rows in ([],[row,row],None):
   with self.assertRaises(TransitionError):current_atlas_image(rows)

 def test_interrupted_transition_blocks_retry_until_exact_checkpoint_cleared(self):
  with tempfile.TemporaryDirectory() as directory:
   checkpoint=TransitionCheckpoint(directory,expected_uid=os.getuid())
   previous='sha256:'+'a'*64; candidate='sha256:'+'b'*64
   checkpoint.begin(previous,candidate)
   self.assertEqual(checkpoint.path.stat().st_mode & 0o777,0o600)
   with self.assertRaises(TransitionError):checkpoint.begin(previous,candidate)
   with self.assertRaises(TransitionError):checkpoint.clear(candidate,previous)
   self.assertTrue(checkpoint.path.exists())
   checkpoint.clear(previous,candidate)
   self.assertFalse(checkpoint.path.exists())
   checkpoint.path.symlink_to(Path(directory)/'missing')
   with self.assertRaises(TransitionError):checkpoint.begin(previous,candidate)
   with self.assertRaises(TransitionError):checkpoint.clear(previous,candidate)

 def test_failed_update_restores_previous_or_preserves_checkpoint(self):
  previous='sha256:'+'a'*64; candidate='sha256:'+'b'*64
  for rollback_works in (True,False):
   with self.subTest(rollback_works=rollback_works),tempfile.TemporaryDirectory() as directory:
    checkpoint=TransitionCheckpoint(directory,expected_uid=os.getuid()); calls=[]
    def activate(image):
     calls.append(image)
     if image==previous and not rollback_works:raise RuntimeError('rollback failure')
    with self.assertRaises(TransitionError):transition(previous,candidate,checkpoint,activate,lambda image:image==previous)
    self.assertEqual(calls,[candidate,previous])
    self.assertEqual(checkpoint.path.exists(),not rollback_works)

 def test_success_clears_checkpoint_after_verification(self):
  previous='sha256:'+'a'*64; candidate='sha256:'+'b'*64
  with tempfile.TemporaryDirectory() as directory:
   checkpoint=TransitionCheckpoint(directory,expected_uid=os.getuid());calls=[]
   transition(previous,candidate,checkpoint,calls.append,lambda image:image==candidate)
   self.assertEqual(calls,[candidate]);self.assertFalse(checkpoint.path.exists())
