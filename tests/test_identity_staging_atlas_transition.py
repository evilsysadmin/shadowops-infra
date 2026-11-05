import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from identity_staging_atlas_transition import current_atlas_image, TransitionError, IMAGE, CONFIG, TARGET, PROJECT


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
