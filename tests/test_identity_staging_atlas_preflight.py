import importlib.util
import json
import unittest
from pathlib import Path

path=Path(__file__).resolve().parents[1]/'host'/'identity-atlas-staging-preflight.py'
spec=importlib.util.spec_from_file_location('atlas_preflight_host',path)
preflight=importlib.util.module_from_spec(spec);spec.loader.exec_module(preflight)
DIGEST='sha256:'+'a'*64
SHA='b'*40
LABELS=json.dumps({'org.opencontainers.image.revision':SHA,'org.opencontainers.image.source':'https://github.com/evilsysadmin/shadowops-infra'})

class AtlasPreflightTests(unittest.TestCase):
 def test_run_uses_fixed_network_and_readonly_config_and_cleans_up(self):
  calls=[]
  def run(args,timeout=120):
   calls.append(args)
   return LABELS if args[1:3]==['image','inspect'] else ''
  self.assertEqual(preflight.execute(DIGEST,SHA,runner=run,nonce='c'*24),'IDENTITY_ATLAS_PREFLIGHT_OK source_sha='+SHA+' digest='+DIGEST)
  self.assertEqual(calls[-1],['docker','network','rm','shadowops-identity-atlas-probe-'+'c'*24])
  command=next(c for c in calls if c[1:2]==['run'])
  self.assertIn('--read-only',command)
  self.assertIn('--cap-drop',command)
  self.assertIn('type=bind,src=/etc/shadowops/identity-staging/atlas-service.json,dst=/run/secrets/identity-staging.json,readonly',command)
  self.assertEqual(command[-1],'preflight')
  self.assertFalse(any('password' in item.lower() for item in command))
 def test_failed_probe_cleans_network_and_wrong_image_never_creates_one(self):
  calls=[]
  def failed(args,timeout=120):
   calls.append(args)
   if args[1:2]==['run']:raise preflight.PreflightError('synthetic failure')
   return LABELS if args[1:3]==['image','inspect'] else ''
  with self.assertRaises(preflight.PreflightError):preflight.execute(DIGEST,SHA,runner=failed,nonce='d'*24)
  self.assertEqual(calls[-1],['docker','network','rm','shadowops-identity-atlas-probe-'+'d'*24])
  calls=[]
  def wrong(args,timeout=120):
   calls.append(args)
   return '{}' if args[1:3]==['image','inspect'] else ''
  with self.assertRaises(preflight.PreflightError):preflight.execute(DIGEST,SHA,runner=wrong,nonce='e'*24)
  self.assertFalse(any(c[1:3]==['network','create'] for c in calls))
