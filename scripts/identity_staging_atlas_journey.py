"""Disposable staging account/admin journey on a private Atlas canary.

Only a random canary account may be promoted or removed. Successful admin
inventory access leaves its normal audit entry; no user audit is deleted.
"""
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import stat
import tempfile
import re
import secrets
import socket
import ssl
import subprocess
import sys

from identity_staging_atlas import _connection
from identity_staging_atlas_backup import IMAGE

HOST='id-staging.shadowops.dpdns.org'
ORIGIN='https://'+HOST
COOKIE='__Host-shadowops_sso_staging'
NAME=re.compile(r'identitycanary_[a-f0-9]{16}')
SUBJECT=re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}')
NETWORK=re.compile(r'shadowops-identity-atlas-canary-net-[a-f0-9]{24}')

class JourneyError(ValueError): pass



class JourneyCheckpoint:
    """A private durable fence against retrying an interrupted journey."""
    def __init__(self,path=Path('/var/lib/shadowops/identity-staging/atlas-canary-pending.json')):
        self.path=Path(path)

    def _sync_directory(self):
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def _read(self):
        meta=self.path.lstat()
        if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or
            meta.st_uid!=os.geteuid() or meta.st_mode&0o077 or meta.st_size>1024):
            raise JourneyError('Invalid pending canary checkpoint')
        def unique(pairs):
            result={}
            for key,item in pairs:
                if key in result: raise JourneyError('Ambiguous pending canary checkpoint')
                result[key]=item
            return result
        value=json.loads(self.path.read_text(),object_pairs_hook=unique)
        if (not isinstance(value,dict) or set(value)!={'schema','environment','name','subject'} or
            type(value['schema']) is not int or value['schema']!=1 or value['environment']!='staging' or
            not isinstance(value['name'],str) or not NAME.fullmatch(value['name']) or
            (value['subject'] is not None and (not isinstance(value['subject'],str) or not SUBJECT.fullmatch(value['subject'])))):
            raise JourneyError('Invalid pending canary checkpoint')
        return value

    def begin(self,name):
        if not NAME.fullmatch(name): raise JourneyError('Invalid synthetic identity')
        value={'schema':1,'environment':'staging','name':name,'subject':None}
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            try:
                existing=self._read()
                print('IDENTITY_ATLAS_CANARY_RECOVERY_PENDING name='+existing['name'],file=sys.stderr)
            except Exception:
                pass
            raise JourneyError('Pending canary recovery requires operator review') from None
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(value,stream,separators=(',',':'))
            stream.flush();os.fsync(stream.fileno())
        self._sync_directory()

    def set_subject(self,name,subject):
        value=self._read()
        if value['name']!=name or value['subject'] is not None or not SUBJECT.fullmatch(subject):
            raise JourneyError('Canary checkpoint does not match')
        value['subject']=subject
        fd,temp=tempfile.mkstemp(dir=self.path.parent,prefix='.atlas-canary-pending-')
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as stream:
                json.dump(value,stream,separators=(',',':'))
                stream.flush();os.fsync(stream.fileno())
            os.replace(temp,self.path)
            self._sync_directory()
        finally:
            Path(temp).unlink(missing_ok=True)

    def clear(self,name):
        if self._read()['name']!=name: raise JourneyError('Canary checkpoint does not match')
        self.path.unlink()
        self._sync_directory()

def request(port, ca, path, payload, cookie=None):
    context=ssl.create_default_context(cafile=str(ca))
    conn=http.client.HTTPSConnection(HOST,port,timeout=8,context=context)
    conn._create_connection=lambda address, timeout=8, source_address=None: socket.create_connection(('127.0.0.1',port),timeout,source_address)
    headers={'Host':HOST,'Origin':ORIGIN,'Content-Type':'application/json'}
    if cookie: headers['Cookie']=cookie
    try:
        conn.request('POST',path,body=json.dumps(payload,separators=(',',':')).encode(),headers=headers)
        response=conn.getresponse()
        body=response.read(1048577)
        if len(body)>1048576: raise JourneyError('Response too large')
        return response.status, response.getheader('Set-Cookie','')
    except (OSError,ValueError,http.client.HTTPException):
        raise JourneyError('Canary request failed') from None
    finally: conn.close()


def mongo_action(uri, network, name, operation, subject=None, runner=subprocess.run):
    if not NETWORK.fullmatch(network) or not NAME.fullmatch(name) or operation not in {'lookup','promote','cleanup'}:
        raise JourneyError('Invalid synthetic operation')
    if operation in {'promote','cleanup'} and (not isinstance(subject,str) or not SUBJECT.fullmatch(subject)):
        raise JourneyError('Invalid synthetic subject')
    _connection(uri)
    # URI and account names are sent only through stdin. Mongo output is
    # captured and parsed as fixed markers; errors are never echoed.
    prefix='const uri='+json.dumps(uri)+'; const name='+json.dumps(name)+'; const subject='+json.dumps(subject)+';\n'
    common='''const c=new Mongo(uri); const d=c.getDB("shadowops_identity_staging");
const f={environment:"staging",source:"shadowops-identity",alias_key:name};
'''
    scripts={
      'lookup': '''const a=d.pending_accounts.find(f).limit(2).toArray(); if(a.length!==1 || a[0].state!=="active" || a[0].credentials_disabled!==false || a[0].role!=="user") throw Error("lookup"); print("CANARY_SUBJECT:"+a[0]._id);''',
      'promote': '''const r=d.pending_accounts.updateOne({...f,_id:subject,state:"active",credentials_disabled:false,role:"user"},{$set:{role:"admin"}}); if(r.matchedCount!==1 || r.modifiedCount!==1) throw Error("promote"); print("CANARY_PROMOTED");''',
      'cleanup': '''const a=d.pending_accounts.findOne({...f,_id:subject}); if(!a) {if(d.pending_accounts.findOne({_id:subject})) throw Error("subject reused"); d.sessions.deleteMany({environment:"staging",subject:subject}); print("CANARY_CLEAN");} else { if(a.role!=="user" && a.role!=="admin") throw Error("role"); const r=d.pending_accounts.updateOne({...f,_id:subject},{$set:{role:"user",credentials_disabled:true}}); if(r.matchedCount!==1) throw Error("disable"); d.sessions.deleteMany({environment:"staging",subject:subject}); const q=d.pending_accounts.deleteOne({...f,_id:subject,role:"user",credentials_disabled:true}); if(q.deletedCount!==1) throw Error("delete"); print("CANARY_CLEAN"); }''',
    }
    args=['docker','run','--rm','-i','--network',network,'--read-only',
          '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--user','65532:65532',
          '--env','HOME=/tmp','--cap-drop','ALL','--security-opt','no-new-privileges:true',
          '--pids-limit','128','--memory','256m','--entrypoint','mongosh',IMAGE,
          '--nodb','--norc','--quiet','--file','/dev/stdin']
    try:
        result=runner(args,input=prefix+common+scripts[operation],text=True,capture_output=True,timeout=45,
                      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
        if result.returncode or len(result.stdout)>4096: raise JourneyError('Synthetic Mongo operation failed')
        lines=result.stdout.splitlines()
        if operation=='lookup':
            matches=[line.removeprefix('CANARY_SUBJECT:') for line in lines if line.startswith('CANARY_SUBJECT:')]
            if len(matches)!=1 or not SUBJECT.fullmatch(matches[0]): raise JourneyError('Synthetic lookup failed')
            return matches[0]
        marker={'promote':'CANARY_PROMOTED','cleanup':'CANARY_CLEAN'}[operation]
        if marker not in lines: raise JourneyError('Synthetic Mongo receipt missing')
        return None
    except (OSError,subprocess.SubprocessError,ValueError,TypeError):
        raise JourneyError('Synthetic Mongo operation failed') from None


def recover_pending(checkpoint,uri,network,*,mongo=mongo_action):
    """Clean only the UUID recorded before a synthetic role grant."""
    pending=checkpoint._read()
    subject=pending['subject']
    if subject is None:
        print('IDENTITY_ATLAS_CANARY_MANUAL_REVIEW_REQUIRED name='+pending['name'],file=sys.stderr)
        raise JourneyError('Ambiguous registration needs manual review')
    mongo(uri,network,pending['name'],'cleanup',subject)
    checkpoint.clear(pending['name'])
    return 'IDENTITY_ATLAS_CANARY_RECOVERY_OK'


def perform(port, network, ca, config, *, http=request, mongo=mongo_action, nonce=None, checkpoint=None):
    if not isinstance(port,int) or not 1024<=port<=65535 or not NETWORK.fullmatch(network):
        raise JourneyError('Invalid isolated canary endpoint')
    suffix=nonce if nonce is not None else secrets.token_hex(8)
    if not re.fullmatch(r'[a-f0-9]{16}',suffix): raise JourneyError('Invalid synthetic identity')
    name='identitycanary_'+suffix
    password=secrets.token_urlsafe(32)
    uri=config.get('admin_inventory_mongo_uri')
    _connection(uri)
    checkpoint=checkpoint if checkpoint is not None else JourneyCheckpoint()
    checkpoint.begin(name)
    registered=False
    registration_uncertain=True
    subject=None
    try:
        status,_=http(port,ca,'/api/identity/register',{'username':name,'password':password})
        if status!=201:
            registration_uncertain=not (400<=status<500)
            raise JourneyError('Synthetic registration failed')
        registered=True
        registration_uncertain=False
        subject=mongo(uri,network,name,'lookup')
        checkpoint.set_subject(name,subject)
        status,header=http(port,ca,'/api/identity/login',{'username':name,'password':password})
        cookies=SimpleCookie();cookies.load(header)
        if status!=204 or COOKIE not in cookies or not cookies[COOKIE].value:
            raise JourneyError('Synthetic login failed')
        cookie=COOKIE+'='+cookies[COOKIE].value
        query={'after':'','limit':20}
        if http(port,ca,'/api/identity/admin/accounts',query,cookie)[0]!=401:
            raise JourneyError('Synthetic user unexpectedly authorized')
        mongo(uri,network,name,'promote',subject)
        if http(port,ca,'/api/identity/admin/accounts',query,cookie)[0]!=200:
            raise JourneyError('Synthetic admin rejected')
    finally:
        if registration_uncertain:
            print('IDENTITY_ATLAS_CANARY_REGISTRATION_UNCERTAIN name='+name,file=sys.stderr)
        elif not registered:
            checkpoint.clear(name)
        if registered:
            try:
                if subject is None: subject=mongo(uri,network,name,'lookup')
                mongo(uri,network,name,'cleanup',subject)
                checkpoint.clear(name)
            except Exception:
                # The generated name is non-secret and lets an operator find
                # the synthetic account if Atlas becomes unavailable mid-test.
                print('IDENTITY_ATLAS_CANARY_CLEANUP_REQUIRED name='+name,file=sys.stderr)
                raise JourneyError('Synthetic account cleanup failed') from None
    return 'IDENTITY_ATLAS_ADMIN_JOURNEY_OK'
