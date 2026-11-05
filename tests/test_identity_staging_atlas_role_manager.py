import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_atlas_role_manager as manager

PROJECT='a'*24
BASE='mongodb+srv://{}:synthetic-password-12345@cluster.mongodb.net/?retryWrites=true&w=majority'
URIS=[BASE.format(x) for x in ('runtimeuser','inventoryuser','backupuser')]

class FakeAtlas:
 def __init__(self):
  self.roles={};self.users={name:{'username':name,'databaseName':'admin','roles':[{'roleName':'readWriteAnyDatabase' if name!='backupuser' else 'readAnyDatabase','databaseName':'admin'}],'scopes':[{'name':'Cluster0','type':'CLUSTER'}]} for name in ('runtimeuser','inventoryuser','backupuser')};self.calls=[];self.fail_user=None
 def request(self,method,path,body=None,allow_missing=False):
  self.calls.append((method,path,copy.deepcopy(body)))
  if path.endswith('/clusters'):
   return {'totalCount':1,'results':[{'name':'Cluster0','connectionStrings':{'standardSrv':'mongodb+srv://cluster.mongodb.net'}}]}
  if '/customDBRoles/roles/' in path:
   return copy.deepcopy(self.roles.get(path.rsplit('/',1)[1]))
  if path.endswith('/customDBRoles/roles') and method=='POST':
   self.roles[body['roleName']]=copy.deepcopy(body);return {}
  if '/databaseUsers/admin/' in path:
   name=path.rsplit('/',1)[1]
   if method=='GET':return copy.deepcopy(self.users[name])
   if method=='PATCH':
    if name==self.fail_user:
     self.fail_user=None
     raise manager.AtlasRoleError('synthetic failure')
    self.users[name]['roles']=copy.deepcopy(body['roles'])
    if 'scopes' in body:self.users[name]['scopes']=copy.deepcopy(body['scopes'])
    return {}
  raise AssertionError('Unexpected API request')

class AtlasRoleManagerTests(unittest.TestCase):
 def test_creates_only_expected_roles_and_assigns_each_dedicated_user(self):
  api=FakeAtlas();plan=manager.build_plan(api,PROJECT,URIS)
  self.assertTrue(all(method=='GET' for method,_,_ in api.calls))
  manager.apply_plan(api,PROJECT,plan)
  self.assertEqual(set(api.roles),set(manager.ROLE_BY_KIND.values()))
  for kind,name in zip(('runtime','inventory','backup'),('runtimeuser','inventoryuser','backupuser')):
   self.assertEqual(api.users[name]['roles'],[{'roleName':manager.ROLE_BY_KIND[kind],'databaseName':'admin'}])
   self.assertEqual(api.users[name]['scopes'],[{'name':'Cluster0','type':'CLUSTER'}])
  again=manager.build_plan(api,PROJECT,URIS);before=len(api.calls);manager.apply_plan(api,PROJECT,again)
  self.assertFalse(any(method in ('POST','PATCH') for method,_,_ in api.calls[before:]))
 def test_conflicting_role_or_unexpected_user_privileges_cause_no_writes(self):
  for scenario in ('conflicting_role','unexpected_user'):
   api=FakeAtlas()
   if scenario=='conflicting_role':api.roles[manager.ROLE_BY_KIND['runtime']]={'roleName':manager.ROLE_BY_KIND['runtime'],'actions':[{'action':'FIND','resources':[{'db':'other','collection':'users'}]}],'inheritedRoles':[]}
   else:api.users['backupuser']['roles']=[{'roleName':'atlasAdmin','databaseName':'admin'}]
   with self.subTest(scenario=scenario),self.assertRaises(manager.AtlasRoleError):manager.build_plan(api,PROJECT,URIS)
   self.assertFalse(any(method in ('POST','PATCH') for method,_,_ in api.calls))
 def test_failed_assignment_restores_previous_user_roles(self):
  api=FakeAtlas();before=copy.deepcopy(api.users);plan=manager.build_plan(api,PROJECT,URIS);api.fail_user='inventoryuser'
  with self.assertRaises(manager.AtlasRoleError) as error:manager.apply_plan(api,PROJECT,plan)
  self.assertIn('verify user roles and retry',str(error.exception))
  self.assertEqual(api.users,before)
 def test_unknown_patch_result_still_restores_attempted_user(self):
  api=FakeAtlas();before=copy.deepcopy(api.users);plan=manager.build_plan(api,PROJECT,URIS)
  original=api.request
  def timeout_after_write(method,path,body=None,allow_missing=False):
   if method=='PATCH' and path.endswith('/inventoryuser') and api.fail_user is None:
    api.fail_user='triggered'
    original(method,path,body,allow_missing)
    raise manager.AtlasRoleError('synthetic timeout')
   return original(method,path,body,allow_missing)
  api.request=timeout_after_write
  with self.assertRaises(manager.AtlasRoleError) as error:manager.apply_plan(api,PROJECT,plan,pause=lambda seconds:None)
  self.assertIn('verify user roles and retry',str(error.exception))
  self.assertEqual(api.users,before)
 def test_wrong_project_cluster_is_rejected_before_any_write(self):
  api=FakeAtlas();original=api.request
  def wrong_cluster(method,path,body=None,allow_missing=False):
   if path.endswith('/clusters'):
    return {'totalCount':1,'results':[{'connectionStrings':{'standardSrv':'mongodb+srv://other.mongodb.net'}}]}
   return original(method,path,body,allow_missing)
  api.request=wrong_cluster
  with self.assertRaises(manager.AtlasRoleError):manager.build_plan(api,PROJECT,URIS)
  self.assertFalse(any(method in ('POST','PATCH') for method,_,_ in api.calls))
 def test_rejects_invalid_project_and_reused_users(self):
  for project,uris in [('other',URIS),(PROJECT,[URIS[0],URIS[0],URIS[2]])]:
   api=FakeAtlas()
   with self.subTest(project=project),self.assertRaises((manager.AtlasRoleError,ValueError)):manager.build_plan(api,project,uris)
   self.assertEqual(api.calls,[])

 def test_rollback_attempts_every_user_and_reports_incomplete_recovery(self):
  api=FakeAtlas();plan=manager.build_plan(api,PROJECT,URIS)
  original=api.request
  def fail_after_first_update(method,path,body=None,allow_missing=False):
   if method=='PATCH' and path.endswith('/inventoryuser'):raise manager.AtlasRoleError('synthetic failure')
   if method=='PATCH' and path.endswith('/runtimeuser') and body['roles'][0]['roleName']=='readWriteAnyDatabase':raise manager.AtlasRoleError('synthetic rollback failure')
   return original(method,path,body,allow_missing)
  api.request=fail_after_first_update
  with self.assertRaises(manager.AtlasRoleError) as error:manager.apply_plan(api,PROJECT,plan,pause=lambda seconds:None)
  self.assertEqual(str(error.exception),'Atlas role update failed; rollback requires review')

 def test_plan_output_contains_no_usernames_or_credentials(self):
  import contextlib
  import io
  import os
  from unittest.mock import patch
  api=FakeAtlas();out=io.StringIO()
  env={'IDENTITY_ATLAS_PROJECT_ID':PROJECT,'ATLAS_API_PUBLIC_KEY':'synthetic-public','ATLAS_API_PRIVATE_KEY':'synthetic-private','IDENTITY_ATLAS_STAGING_RUNTIME_URI':URIS[0],'IDENTITY_ATLAS_STAGING_INVENTORY_URI':URIS[1],'IDENTITY_ATLAS_STAGING_BACKUP_URI':URIS[2]}
  with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',['manager','plan']),patch.object(manager,'Client',return_value=api),contextlib.redirect_stdout(out):
   self.assertEqual(manager.main(),0)
  text=out.getvalue()
  self.assertIn('IDENTITY_ATLAS_USER_PLAN kind=runtime',text)
  for secret in ('runtimeuser','inventoryuser','backupuser','synthetic-password','synthetic-private','cluster.mongodb.net'):
   self.assertNotIn(secret,text)

 def test_user_change_after_plan_is_not_overwritten(self):
  api=FakeAtlas();plan=manager.build_plan(api,PROJECT,URIS)
  api.users['inventoryuser']['roles']=[{'roleName':'atlasAdmin','databaseName':'admin'}]
  with self.assertRaises(manager.AtlasRoleError):manager.apply_plan(api,PROJECT,plan,pause=lambda seconds:None)
  self.assertEqual(api.users['inventoryuser']['roles'],[{'roleName':'atlasAdmin','databaseName':'admin'}])
  self.assertEqual(api.users['runtimeuser']['roles'],[{'roleName':'readWriteAnyDatabase','databaseName':'admin'}])
 def test_api_client_does_not_follow_redirects(self):
  redirect=manager.NoRedirect()
  self.assertIsNone(redirect.redirect_request(None,None,302,'','https://example.invalid','https://example.invalid'))
