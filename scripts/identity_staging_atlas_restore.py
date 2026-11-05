"""Restore a quarantined Atlas snapshot into a disposable, networkless Mongo.

Only docker exec reaches this database. No Atlas URI, backup key, live password
or live session enters the container. Plaintext results never leave this process.
"""
import json
import re
import secrets
import subprocess
import time

from identity_staging_atlas_backup import IMAGE
from identity_staging_backup import (BackupError, COLLECTIONS, MAX_BYTES,
    quarantine_restore, restore_script)

LABEL='shadowops.identity.atlas-restore=staging'
CID=re.compile(r'[a-f0-9]{12,64}')
MARKER='IDENTITY_ATLAS_QUARANTINE_RESTORE_OK'


def run(args, data=None, timeout=120):
    try:
        result=subprocess.run(args,input=data,text=True,capture_output=True,
            timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
        if result.returncode or len(result.stdout.encode())>MAX_BYTES:
            raise BackupError('Isolated restore command failed')
        return result.stdout.strip()
    except (OSError,subprocess.SubprocessError):
        raise BackupError('Isolated restore command failed') from None


def verify_container(value):
    if (not isinstance(value,dict) or value.get('Config',{}).get('Image')!=IMAGE
            or value.get('Config',{}).get('Labels',{}).get('shadowops.identity.atlas-restore')!='staging'
            or value.get('Config',{}).get('User')!='999:999'):
        raise BackupError('Unsafe restore container')
    host=value.get('HostConfig',{})
    if (host.get('NetworkMode')!='none' or host.get('PortBindings')
            or not host.get('ReadonlyRootfs') or host.get('Privileged')
            or host.get('CapDrop')!=['ALL'] or host.get('Binds')
            or host.get('SecurityOpt')!=['no-new-privileges:true']
            or set(host.get('Tmpfs',{}))!={'/data/db','/data/configdb','/tmp'}
            or any(mount.get('Type')!='tmpfs' for mount in value.get('Mounts',[]))):
        raise BackupError('Unsafe restore container')


def rehearse(snapshot, *, runner=run, nonce=None, pause=time.sleep):
    if snapshot.get('schema')!=2:
        raise BackupError('Schema 2 restore rehearsal required')
    # The original snapshot (including real hashes and sessions) is never sent
    # to Mongo. The existing restore primitive quarantines the plan again.
    plan=quarantine_restore(snapshot)
    suffix=nonce if nonce is not None else secrets.token_hex(12)
    if not isinstance(suffix,str) or not re.fullmatch(r'[a-f0-9]{24}',suffix):
        raise BackupError('Invalid restore identity')
    name='shadowops-identity-atlas-restore-'+suffix
    if runner(['docker','ps','--all','--filter','label='+LABEL,'--format','{{.ID}}']):
        raise BackupError('Previous restore container requires operator cleanup')
    password=secrets.token_hex(32)
    attempted=False
    try:
        attempted=True
        container=runner(['docker','run','--detach','--name',name,'--label',LABEL,
            '--network','none','--read-only','--user','999:999',
            '--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--pids-limit','128','--memory','1g','--cpus','0.5',
            '--tmpfs','/data/db:rw,noexec,nosuid,size=512m,uid=999,gid=999',
            '--tmpfs','/data/configdb:rw,noexec,nosuid,size=16m,uid=999,gid=999',
            '--tmpfs','/tmp:rw,noexec,nosuid,size=32m,uid=999,gid=999',
            '--entrypoint','mongod',IMAGE,'--bind_ip','127.0.0.1',
            '--replSet','identity-restore-rs','--wiredTigerCacheSizeGB','0.25'])
        if not CID.fullmatch(container):raise BackupError('Missing restore container identity')
        verify_container(json.loads(runner(['docker','inspect',container,'--format','{{json .}}'])))
        def mongo(script):
            return runner(['docker','exec','-i',container,'mongosh','--quiet','--norc',
                'mongodb://127.0.0.1:27017/?directConnection=true','--file','/dev/stdin'],data=script)
        for _ in range(30):
            try:
                mongo('if(db.adminCommand({ping:1}).ok!==1) quit(1);');break
            except BackupError:pause(1)
        else:raise BackupError('Restore database unavailable')
        # No external connection exists, so authentication is only a test of
        # the existing restore primitive, not the isolation boundary.
        mongo('rs.initiate({_id:"identity-restore-rs",members:[{_id:0,host:"127.0.0.1:27017"}]});\n'
            'for(let i=0;i<30&&!db.hello().isWritablePrimary;i++) sleep(1000);\n'
            'if(!db.hello().isWritablePrimary) throw Error("primary");\n'
            'db.getSiblingDB("admin").createUser({user:"identity_root",pwd:'+json.dumps(password)+',roles:["root"]});\n'
            'const d=db.getSiblingDB("shadowops_identity_staging");\n'
            'for(const n of '+json.dumps(sorted(COLLECTIONS))+') d.createCollection(n);')
        if mongo(restore_script(password,snapshot))!='IDENTITY_STAGING_QUARANTINE_RESTORE_OK':
            raise BackupError('Restore receipt missing')
        expected=plan
        script='const d=db.getSiblingDB("shadowops_identity_staging");const out={};\n'
        script+='for(const n of '+json.dumps(sorted(COLLECTIONS))+') out[n]=EJSON.serialize(d.getCollection(n).find({}).limit(10001).toArray(),{relaxed:false});\nprint(JSON.stringify(out));'
        actual=json.loads(mongo(script))
        def canonical(rows):
            return sorted(json.dumps(row,sort_keys=True,separators=(',',':')) for row in rows)
        if (set(actual)!=COLLECTIONS or any(not isinstance(actual[n],list) or
                canonical(actual[n])!=canonical(expected['collections'][n]) for n in COLLECTIONS)):
            raise BackupError('Restored quarantine differs from snapshot')
        # Prove the guard refuses a nonempty target, even for empty backups.
        mongo('db.getSiblingDB("shadowops_identity_staging").sessions.insertOne({_id:"restore-denial-sentinel"});')
        denial='let denied=false;try{'+restore_script(password,snapshot)+'}catch(error){if(!String(error).includes("restore refuses nonempty destination")) throw error;denied=true;}\n'
        denial+='if(!denied) throw Error("restore accepted nonempty destination");print("DENIED");'
        if mongo(denial)!='DENIED':raise BackupError('Restore accepted a nonempty destination')
        if mongo('if(!db.getSiblingDB("shadowops_identity_staging").sessions.findOne({_id:"restore-denial-sentinel"})) throw Error("sentinel");print("UNCHANGED");')!='UNCHANGED':
            raise BackupError('Rejected restore changed destination')
    finally:
        if attempted:
            ids=runner(['docker','ps','--all','--filter','name=^/'+name+'$',
                '--filter','label='+LABEL,'--format','{{.ID}}']).splitlines()
            if ids:
                if len(ids)!=1 or not CID.fullmatch(ids[0]):raise BackupError('Ambiguous restore cleanup')
                runner(['docker','rm','--force','--volumes',ids[0]],timeout=30)
    return MARKER
