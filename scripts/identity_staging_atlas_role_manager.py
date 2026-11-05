#!/usr/bin/env python3
"""Manage only the three explicitly supplied staging Identity Atlas users.

The API credential is project-scoped Atlas administration, not a MongoDB URL.
No credentials, usernames, URLs or API response bodies are printed.
"""
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, HTTPRedirectHandler, Request, build_opener

from identity_staging_atlas_provision import validate_inputs
from identity_staging_atlas_roles import payloads

API = 'https://cloud.mongodb.com'
PROJECT = re.compile(r'[a-f0-9]{24}')
MAX_RESPONSE = 1024 * 1024
ROLE_BY_KIND = {'runtime':'shadowops_identity_staging_runtime', 'inventory':'shadowops_identity_staging_inventory', 'backup':'shadowops_identity_staging_backup'}

class AtlasRoleError(ValueError):
    pass

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class Client:
    def __init__(self, public_key, private_key):
        if not isinstance(public_key,str) or not public_key or not isinstance(private_key,str) or not private_key:
            raise AtlasRoleError('Missing Atlas API credentials')
        manager = HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, API, public_key, private_key)
        self.opener = build_opener(NoRedirect(), HTTPDigestAuthHandler(manager))
    def request(self, method, path, body=None, allow_missing=False):
        if not path.startswith('/api/atlas/v2/groups/') or '?' in path or '#' in path or '..' in path:
            raise AtlasRoleError('Invalid Atlas API request')
        data = None if body is None else json.dumps(body,separators=(',',':')).encode()
        request = Request(API + path, method=method, data=data, headers={'Accept':'application/vnd.atlas.2024-05-30+json','Content-Type':'application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE+1)
                if len(raw)>MAX_RESPONSE:
                    raise AtlasRoleError('Atlas API response exceeds bound')
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            if allow_missing and exc.code == 404:
                return None
            raise AtlasRoleError('Atlas API request failed') from None
        except (URLError, OSError, ValueError, TypeError):
            raise AtlasRoleError('Atlas API request failed') from None


def canonical_role(value):
    try:
        if not isinstance(value,dict) or value.get('inheritedRoles',[]) != []:
            raise ValueError()
        seen=set()
        for row in value['actions']:
            action=row['action']
            if not isinstance(action,str) or not isinstance(row['resources'],list) or not row['resources']:
                raise ValueError()
            for resource in row['resources']:
                if not isinstance(resource,dict) or resource.get('cluster',False) is not False:
                    raise ValueError()
                entry=(action,resource['db'],resource['collection'])
                if entry in seen or not all(isinstance(x,str) and x for x in entry):
                    raise ValueError()
                seen.add(entry)
        return value['roleName'],frozenset(seen)
    except (KeyError, TypeError, ValueError):
        raise AtlasRoleError('Unexpected Atlas custom role') from None


def permitted_existing_roles(value,target):
    if not isinstance(value,list) or not value:
        raise AtlasRoleError('Atlas database user has unexpected roles')
    result=[]
    for role in value:
        if not isinstance(role,dict) or set(role)-{'roleName','databaseName','collectionName'} or role.get('collectionName'):
            raise AtlasRoleError('Atlas database user has unexpected roles')
        name,db=role.get('roleName'),role.get('databaseName')
        if not ((name in {'readWriteAnyDatabase','readAnyDatabase'} and db=='admin') or
                (name in {'readWrite','read'} and db=='shadowops_identity_staging') or
                (name==target and db=='admin')):
            raise AtlasRoleError('Atlas database user has unexpected roles')
        result.append({'roleName':name,'databaseName':db})
    return result


def build_plan(client,project,uris):
    if not isinstance(project,str) or not PROJECT.fullmatch(project):
        raise AtlasRoleError('Invalid Atlas project ID')
    normalized=validate_inputs(*uris)
    users=[unquote(urlsplit(uri).username,errors='strict') for uri in normalized]
    if len(set(users))!=3:
        raise AtlasRoleError('Atlas database users must be distinct')
    prefix='/api/atlas/v2/groups/'+project
    # Bind the project to the exact Atlas SRV host in the three staging URLs.
    # Refuse incomplete pagination rather than touching an ambiguous project.
    clusters=client.request('GET',prefix+'/clusters')
    if not isinstance(clusters,dict) or not isinstance(clusters.get('results'),list):
        raise AtlasRoleError('Atlas project cluster inventory unavailable')
    rows=clusters['results']
    if type(clusters.get('totalCount')) is not int or clusters['totalCount']!=len(rows):
        raise AtlasRoleError('Atlas project cluster inventory incomplete')
    target_host=urlsplit(normalized[0]).hostname
    matches=[]
    for row in rows:
        if not isinstance(row,dict):
            raise AtlasRoleError('Atlas project cluster inventory invalid')
        uri=(row.get('connectionStrings') or {}).get('standardSrv','')
        parsed=urlsplit(uri)
        if parsed.scheme=='mongodb+srv' and parsed.hostname==target_host:
            matches.append(row)
    if len(matches)!=1:
        raise AtlasRoleError('Atlas project does not uniquely contain staging cluster')
    requested={role['roleName']:role for role in payloads() if role['roleName'] in ROLE_BY_KIND.values()}
    role_plan=[]
    for kind,target in ROLE_BY_KIND.items():
        role=requested[target]
        existing=client.request('GET',prefix+'/customDBRoles/roles/'+quote(target,safe=''),allow_missing=True)
        if existing is not None and canonical_role(existing)!=canonical_role(role):
            raise AtlasRoleError('Existing Atlas custom role conflicts')
        role_plan.append((kind,role,existing is None))
    user_plan=[]
    for (kind,target),username in zip(ROLE_BY_KIND.items(),users):
        path=prefix+'/databaseUsers/admin/'+quote(username,safe='')
        current=client.request('GET',path)
        if not isinstance(current,dict) or current.get('username')!=username or current.get('databaseName')!='admin':
            raise AtlasRoleError('Unexpected Atlas database user')
        old_roles=permitted_existing_roles(current.get('roles'),target)
        scopes=current.get('scopes')
        if scopes is not None and (not isinstance(scopes,list) or any(not isinstance(x,dict) or set(x)!={'name','type'} for x in scopes)):
            raise AtlasRoleError('Unexpected Atlas database user scopes')
        user_plan.append((kind,path,old_roles,scopes,target))
    return role_plan,user_plan


def apply_plan(client,project,plan,pause=time.sleep):
    roles,users=plan
    prefix='/api/atlas/v2/groups/'+project
    for _,role,missing in roles:
        if missing:
            client.request('POST',prefix+'/customDBRoles/roles',role)
    # Atlas can take time to propagate a newly created custom role. Do not
    # alter a user until the API returns the exact expected role definition.
    for _,role,_ in roles:
        path=prefix+'/customDBRoles/roles/'+quote(role['roleName'],safe='')
        for attempt in range(30):
            current=client.request('GET',path,allow_missing=True)
            if current is not None:
                if canonical_role(current)!=canonical_role(role):
                    raise AtlasRoleError('Existing Atlas custom role conflicts')
                break
            if attempt==29:
                raise AtlasRoleError('Atlas custom role propagation timed out')
            pause(2)
    changed=[]
    try:
        for kind,path,old_roles,scopes,target in users:
            desired=[{'roleName':target,'databaseName':'admin'}]
            if old_roles==desired:
                continue
            current=client.request('GET',path)
            if permitted_existing_roles(current.get('roles'),target)!=old_roles or current.get('scopes')!=scopes:
                raise AtlasRoleError('Atlas database user changed during update')
            body={'roles':desired}
            if scopes is not None:body['scopes']=scopes
            changed.append((path,old_roles,scopes,target))
            client.request('PATCH',path,body)
        # Confirm the new roles, not just successful PATCH responses. Atlas may
        # return the old view briefly while the update propagates.
        for kind,path,old_roles,scopes,target in users:
            desired=[{'roleName':target,'databaseName':'admin'}]
            for attempt in range(30):
                current=client.request('GET',path)
                current_roles=permitted_existing_roles(current.get('roles'),target)
                if current.get('scopes')!=scopes:
                    raise AtlasRoleError('Atlas database user scope changed')
                if current_roles==desired:
                    break
                if current_roles!=old_roles or attempt==29:
                    raise AtlasRoleError('Atlas user role verification failed')
                pause(2)
    except Exception:
        failures=0
        for path,old_roles,scopes,target in reversed(changed):
            try:
                current=client.request('GET',path)
                current_roles=permitted_existing_roles(current.get('roles'),target)
                if current.get('scopes')!=scopes:
                    raise AtlasRoleError('Atlas database user changed during recovery')
                if current_roles==old_roles:
                    continue
                if current_roles!=[{'roleName':target,'databaseName':'admin'}]:
                    raise AtlasRoleError('Atlas database user changed during recovery')
                body={'roles':old_roles}
                if scopes is not None:body['scopes']=scopes
                client.request('PATCH',path,body)
            except Exception:failures+=1
        if failures:
            raise AtlasRoleError('Atlas role update failed; rollback requires review') from None
        raise AtlasRoleError('Atlas role update failed; verify user roles and retry') from None


def main():
    try:
        if sys.argv[1:] not in (['plan'],['apply']):
            raise AtlasRoleError('Invalid Atlas role operation')
        project=os.environ.get('IDENTITY_ATLAS_PROJECT_ID','')
        uris=[os.environ.get('IDENTITY_ATLAS_STAGING_'+kind+'_URI','') for kind in ('RUNTIME','INVENTORY','BACKUP')]
        client=Client(os.environ.get('ATLAS_API_PUBLIC_KEY',''),os.environ.get('ATLAS_API_PRIVATE_KEY',''))
        plan=build_plan(client,project,uris)
        if sys.argv[1]=='plan':
            for kind,_,missing in plan[0]:print('IDENTITY_ATLAS_ROLE_PLAN kind='+kind+' role='+('create' if missing else 'existing'))
            for kind,_,old,_,target in plan[1]:
                names=','.join(sorted(role['roleName'] for role in old))
                print('IDENTITY_ATLAS_USER_PLAN kind='+kind+' current_roles='+names+' change='+('no' if old==[{'roleName':target,'databaseName':'admin'}] else 'yes'))
        else:
            apply_plan(client,project,plan)
            print('IDENTITY_ATLAS_ROLES_APPLIED verification=api')
        return 0
    except Exception as exc:
        # API error bodies and database URLs may contain credentials. Never print them.
        reason=str(exc) if isinstance(exc,AtlasRoleError) else 'Atlas role operation failed'
        print('IDENTITY_ATLAS_ROLE_BLOCKED reason='+reason,file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
