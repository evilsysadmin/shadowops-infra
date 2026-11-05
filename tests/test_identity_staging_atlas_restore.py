import copy
import json
import os
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_atlas_restore as restore
from identity_staging_backup import BackupError, COLLECTIONS, quarantine_restore


def fixture():
 return {'schema':2,'environment':'staging','database':'shadowops_identity_staging',
  'collections':{**{n:[] for n in COLLECTIONS},'pending_accounts':[{
   '_id':'11111111-1111-4111-8111-111111111111','environment':'staging',
   'state':'active','role':'admin','credentials_disabled':False,
   'credential_hash':'private-original-hash','recovery_digest':'private-recovery',
   'session_version':{'$numberLong':'1'},'credential_version':{'$numberLong':'1'}}],
   'sessions':[{'digest':'private-session'}],'staging_cka_tokens':[{'digest':'private-token'}]}}


def container():
 return {'Config':{'Image':restore.IMAGE,'Labels':{'shadowops.identity.atlas-restore':'staging'},'User':'999:999'},
  'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
   'SecurityOpt':['no-new-privileges:true'],'Tmpfs':{n:'rw' for n in ('/data/db','/data/configdb','/tmp')}},'Mounts':[]}


class RestoreTests(unittest.TestCase):
 def runner(self,*,mismatch=False,fail=False,fail_cleanup=False,unsafe=False,orphan=False):
  calls=[];cid='a'*64
  def run(args,data=None,timeout=120):
   calls.append((args,data))
   if args[:2]==['docker','ps']:
    return cid if orphan or any('name=^/' in arg for arg in args) else ''
   if args[:2]==['docker','run']:return cid
   if args[:2]==['docker','inspect']:
    value=container()
    if unsafe:value['HostConfig']['NetworkMode']='host'
    return json.dumps(value)
   if args[:2]==['docker','rm']:
    if fail_cleanup:raise BackupError('cleanup')
    return ''
   if fail and data and 'const restoreUser' in data:raise BackupError('restore')
   if data and data.startswith('let denied='):return 'DENIED'
   if data and data.startswith('if(!db.'):return 'UNCHANGED'
   if data and 'const restoreUser' in data:return 'IDENTITY_STAGING_QUARANTINE_RESTORE_OK'
   if data and 'print(JSON.stringify(out))' in data:
    value=quarantine_restore(fixture())['collections']
    if mismatch:value['pending_accounts'][0]['role']='admin'
    return json.dumps(value)
   return ''
  return calls,run

 def test_quarantines_before_stdin_and_removes_networkless_container(self):
  calls,run=self.runner()
  self.assertEqual(restore.rehearse(fixture(),runner=run,nonce='b'*24,pause=lambda _:None),restore.MARKER)
  launch=next(args for args,data in calls if args[:2]==['docker','run'])
  self.assertEqual(launch[launch.index('--network')+1],'none')
  self.assertNotIn('--publish',launch);self.assertNotIn('--mount',launch)
  self.assertEqual(calls[-1][0],['docker','rm','--force','--volumes','a'*64])
  transmitted=''.join(data or '' for args,data in calls)
  for private in ('private-original-hash','private-recovery','private-session','private-token'):
   self.assertNotIn(private,transmitted)
  self.assertIn('restore-review',transmitted)

 def test_restore_mismatch_failure_and_unsafe_container_always_cleanup(self):
  for options in ({'mismatch':True},{'fail':True},{'unsafe':True},{'fail_cleanup':True}):
   calls,run=self.runner(**options)
   with self.subTest(options=options),self.assertRaises(BackupError):restore.rehearse(fixture(),runner=run,nonce='b'*24,pause=lambda _:None)
   self.assertEqual(calls[-1][0][:2],['docker','rm'])
   if options.get('unsafe'):self.assertFalse(any(data for args,data in calls))

 def test_unsafe_destinations_and_orphans_are_rejected(self):
  for change in ('network','port','bind','privileged','mount','image','user'):
   value=container()
   if change=='network':value['HostConfig']['NetworkMode']='bridge'
   if change=='port':value['HostConfig']['PortBindings']={'27017/tcp':[{'HostPort':'27017'}]}
   if change=='bind':value['HostConfig']['Binds']=['/host:/data']
   if change=='privileged':value['HostConfig']['Privileged']=True
   if change=='mount':value['Mounts']=[{'Type':'volume'}]
   if change=='image':value['Config']['Image']='mongo:latest'
   if change=='user':value['Config']['User']='0:0'
   with self.subTest(change=change),self.assertRaises(BackupError):restore.verify_container(value)
  calls,run=self.runner(orphan=True)
  with self.assertRaises(BackupError):restore.rehearse(fixture(),runner=run,nonce='b'*24)
  self.assertEqual(len(calls),1)

 def test_invalid_snapshot_and_nonce_never_start_docker(self):
  for value,nonce in [({**fixture(),'environment':'production'},'b'*24),(fixture(),'bad'),({**fixture(),'schema':1},'b'*24)]:
   with self.assertRaises(BackupError):restore.rehearse(value,nonce=nonce,runner=lambda *args,**kwargs:self.fail('unsafe request reached Docker'))
