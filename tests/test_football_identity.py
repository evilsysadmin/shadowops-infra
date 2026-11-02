import copy
import io
from pathlib import Path
import sys
import unittest
from contextlib import contextmanager
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import football_identity as identity

class FootballIdentityBinding(unittest.TestCase):
 def test_only_the_existing_football_proof_is_delivered_to_its_secret_binding(self):
  bundle={'consumers':{'football':'soc1_'+'F'*43,'chronicles':'soc1_'+'C'*43},'signing_seed':'never-send-signing','backup_key':'never-send-backup'}
  before=copy.deepcopy(bundle);calls=[]
  def api(method,path,payload=None):
   calls.append((method,path,payload));return (200,{'deployment_configs':{'production':{'env_vars':{}}}})
  @contextmanager
  def response(*args,**kwargs):
   value=io.BytesIO(b'https://staging.football.shadowops.dpdns.org/?shadowops=central');value.status=200;yield value
  with patch.object(identity,'config_from_env',return_value={}),patch.object(identity,'resolve_existing_host',return_value=('compartment','host')),patch.object(identity,'resolve_vault',return_value=('vault','key','compartment')),patch.object(identity.pages,'existing_project',return_value=True),patch.object(identity.pages,'project_path',return_value='/owned-football'),patch.object(identity.pages,'request',side_effect=api),patch.object(identity.urllib.request,'urlopen',side_effect=response):
   identity.activate(None,{},reader=lambda *args:bundle)
  self.assertEqual(bundle,before)
  mutations=[row for row in calls if row[0]!='GET'];self.assertEqual(len(mutations),1)
  self.assertEqual(mutations[0],('PATCH','/owned-football',{'deployment_configs':{'production':{'env_vars':{identity.KEY:{'type':'secret_text','value':bundle['consumers']['football']}}}}}))
  self.assertNotIn('never-send',str(mutations));self.assertNotIn(bundle['consumers']['chronicles'],str(mutations))
 def test_missing_consumer_fails_before_any_cloud_or_public_call(self):
  with patch.object(identity,'config_from_env',return_value={}),patch.object(identity,'resolve_existing_host',return_value=('compartment','host')),patch.object(identity,'resolve_vault',return_value=('vault','key','compartment')),patch.object(identity.pages,'request') as cloud,patch.object(identity.urllib.request,'urlopen') as public:
   with self.assertRaises(RuntimeError):identity.activate(None,{},reader=lambda *args:{'consumers':{'chronicles':'existing'}})
   cloud.assert_not_called();public.assert_not_called()

if __name__=='__main__':unittest.main()
