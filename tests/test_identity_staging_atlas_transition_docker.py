"""Explicit disposable container rehearsal; never connects to real Identity."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_transition import TransitionCheckpoint, TransitionError, transition
from identity_staging_atlas_backup import IMAGE


@unittest.skipUnless(os.environ.get('IDENTITY_ATLAS_TRANSITION_DOCKER') == '1', 'explicit isolated Docker rehearsal only')
class DockerTransitionTests(unittest.TestCase):
 def test_candidate_failure_restarts_previous_disposable_container(self):
  previous='sha256:'+'a'*64; candidate='sha256:'+'b'*64
  name='identity-transition-test-'+uuid.uuid4().hex
  def docker(*args,check=True):
   return subprocess.run(['docker',*args],capture_output=True,text=True,check=check,timeout=30)
  def activate(image):
   docker('rm','-f',name,check=False)
   docker('run','-d','--name',name,'--network','none','--read-only','--user','999:999',
          '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32',
          '--memory','64m','--label','identity-test-image='+image,
          '--entrypoint','sleep',os.environ.get('IDENTITY_TRANSITION_TEST_IMAGE', IMAGE),'90')
  def verify(image):
   status=docker('inspect','--format','{{.State.Running}} {{index .Config.Labels "identity-test-image"}}',name).stdout.strip()
   return status=='true '+image and image==previous
  try:
   activate(previous)
   with tempfile.TemporaryDirectory() as directory:
    checkpoint=TransitionCheckpoint(directory,expected_uid=os.getuid())
    with self.assertRaises(TransitionError):transition(previous,candidate,checkpoint,activate,verify)
    self.assertTrue(verify(previous));self.assertFalse(checkpoint.path.exists())
  finally:
   docker('rm','-f',name,check=False)
