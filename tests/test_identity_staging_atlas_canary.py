import importlib.util
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
p=Path(__file__).resolve().parents[1]/'host'/'identity-atlas-staging-canary.py'
spec=importlib.util.spec_from_file_location('atlas_canary',p)
canary=importlib.util.module_from_spec(spec);spec.loader.exec_module(canary)

DIGEST='sha256:'+'a'*64
SHA='b'*40
NONCE='c'*24

class CanaryTests(unittest.TestCase):
 def runner(self,*,invalid_port=False,unready=False,fail_remove=False,bad_auth=False,fail_start=False):
  calls=[]
  def run(args,timeout=120):
   calls.append(args)
   if args[:3]==['docker','image','inspect']:
    return json.dumps({'org.opencontainers.image.revision':SHA,'org.opencontainers.image.source':'https://github.com/evilsysadmin/shadowops-infra'})
   if args[:2]==['docker','ps']:
    return 'shadowops-identity-atlas-canary-'+NONCE+'\n'
   if args[:3]==['docker','network','ls']:
    return 'shadowops-identity-atlas-canary-net-'+NONCE+'\n'
   if fail_start and args[:2]==['docker','run']:raise canary.CanaryError('start failed')
   if args[:2]==['docker','port']:
    return '0.0.0.0:12345\n' if invalid_port else '127.0.0.1:12345\n'
   if args[0]=='curl':
    if unready:raise canary.CanaryError('unready')
    if '--write-out' in args:return '200' if bad_auth else '401'
    return 'Administración de cuentas' if args[-1].endswith('/admin') else 'ready'
   if fail_remove and args[:3]==['docker','rm','-f']:raise canary.CanaryError('remove failed')
   return ''
  return calls,run
 def test_success_binds_only_loopback_and_cleans_up(self):
  calls,run=self.runner()
  self.assertTrue(canary.execute(DIGEST,SHA,runner=run,nonce=NONCE,pause=lambda _:None).startswith('IDENTITY_ATLAS_LOOPBACK_CANARY_OK'))
  launch=next(x for x in calls if x[:2]==['docker','run'])
  self.assertIn('127.0.0.1::9443',launch)
  self.assertIn('--read-only',launch)
  self.assertTrue(any(x[:3]==['docker','rm','-f'] for x in calls))
  self.assertTrue(any(x[:3]==['docker','network','rm'] for x in calls))
  self.assertEqual(len([x for x in calls if x[0]=='curl']),3)
 def test_nonloopback_and_unready_fail_with_cleanup(self):
  for options in ({'invalid_port':True},{'unready':True},{'fail_remove':True},{'bad_auth':True},{'fail_start':True}):
   with self.subTest(options=options):
    calls,run=self.runner(**options)
    with self.assertRaises(canary.CanaryError):canary.execute(DIGEST,SHA,runner=run,nonce=NONCE,pause=lambda _:None)
    self.assertTrue(any(x[:3]==['docker','rm','-f'] for x in calls))
    self.assertTrue(any(x[:3]==['docker','network','rm'] for x in calls))
 def test_rejects_bad_image_or_nonce_before_any_command(self):
  calls,run=self.runner()
  for digest,sha,nonce in [('wrong',SHA,NONCE),(DIGEST,'bad',NONCE),(DIGEST,SHA,'bad')]:
   with self.assertRaises(canary.CanaryError):canary.execute(digest,sha,runner=run,nonce=nonce,pause=lambda _:None)
  self.assertEqual(calls,[])

class PrivateCanaryConfigTests(unittest.TestCase):
 def test_requires_private_regular_unique_json(self):
  import os,tempfile
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'config';p.write_text('{"environment":"staging"}');p.chmod(0o400)
   self.assertEqual(canary.read_private_json(p,os.getuid()),{'environment':'staging'})
   p.chmod(0o644)
   with self.assertRaises(canary.CanaryError):canary.read_private_json(p,os.getuid())
   p.chmod(0o400);link=Path(temp)/'link';link.symlink_to(p)
   with self.assertRaises(canary.CanaryError):canary.read_private_json(link,os.getuid())
   p.chmod(0o600);p.write_text('{"environment":"staging","environment":"production"}');p.chmod(0o400)
   with self.assertRaises(canary.CanaryError):canary.read_private_json(p,os.getuid())
