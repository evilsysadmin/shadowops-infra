"""Bounded authenticated staging snapshots and a fail-closed restore plan."""
from __future__ import annotations
import copy
import json
import re
import uuid
from cryptography.fernet import Fernet, InvalidToken

DATABASE='shadowops_identity_staging'
LEGACY_COLLECTIONS={'pending_accounts','sessions','staging_cka_tokens'}
ADMIN_COLLECTIONS={'admin_inventory_audit','staging_application_access_history'}
COLLECTIONS=LEGACY_COLLECTIONS | ADMIN_COLLECTIONS
MAX_BYTES=16*1024*1024


class BackupError(ValueError):pass


def validate_snapshot(value):
    if not isinstance(value,dict) or set(value) != {'schema','environment','database','collections'} or type(value['schema']) is not int or value['schema'] not in (1,2) or value['environment'] != 'staging' or value['database'] != DATABASE:
        raise BackupError('Invalid staging snapshot envelope')
    collections=value['collections']
    expected=LEGACY_COLLECTIONS if value['schema']==1 else COLLECTIONS
    if not isinstance(collections,dict) or set(collections) != expected:
        raise BackupError('Invalid staging snapshot collections')
    for rows in collections.values():
        if not isinstance(rows,list) or len(rows)>10000 or any(not isinstance(row,dict) for row in rows):
            raise BackupError('Invalid or oversized staging snapshot records')
    for row in collections['pending_accounts']:
        subject=row.get('_id')
        try:
            parsed=uuid.UUID(subject)
        except (ValueError,TypeError,AttributeError):
            raise BackupError('Invalid staging account reference') from None
        if parsed.version != 4 or str(parsed) != subject or row.get('environment') != 'staging':
            raise BackupError('Invalid staging account reference')
    if value['schema']==2:
        for row in collections['staging_application_access_history']:
            subject=valid_subject(row.get('subject'))
            application=row.get('application')
            if row.get('environment')!='staging' or application not in {'chess-studio','chronicles','cka-simulator','football','pawn-action'} or row.get('_id')!=subject+':'+application:
                raise BackupError('Invalid application access summary')
            if ejson_date(row.get('first_at'))>ejson_date(row.get('last_at')):
                raise BackupError('Invalid application access timestamps')
        for row in collections['admin_inventory_audit']:
            valid_subject(row.get('actor'))
            if row.get('environment')!='staging' or row.get('action')!='list_accounts' or not isinstance(row.get('_id'),str) or not re.fullmatch('[a-f0-9]{32}',row['_id']) or integer(row.get('returned'))>50:
                raise BackupError('Invalid inventory audit record')
            ejson_date(row.get('at'))


def valid_subject(value):
    try: parsed=uuid.UUID(value)
    except (ValueError,TypeError,AttributeError): raise BackupError('Invalid subject') from None
    if parsed.version!=4 or str(parsed)!=value: raise BackupError('Invalid subject')
    return value


def ejson_date(value):
    if not isinstance(value,dict) or set(value)!={'$date'}: raise BackupError('Invalid snapshot timestamp')
    millis=integer(value['$date'])
    if millis>253402300799999: raise BackupError('Invalid snapshot timestamp')
    return millis


def encrypt_snapshot(value,key):
    validate_snapshot(value)
    raw=json.dumps(value,separators=(',',':')).encode()
    if len(raw)>MAX_BYTES:raise BackupError('Snapshot exceeds bounded pilot size')
    try:return Fernet(key).encrypt(raw)
    except (ValueError,TypeError):raise BackupError('Invalid independent backup key') from None


def decrypt_snapshot(ciphertext,key):
    if not isinstance(ciphertext,bytes) or len(ciphertext)>2*MAX_BYTES:
        raise BackupError('Invalid bounded encrypted snapshot')
    try:
        raw=Fernet(key).decrypt(ciphertext)
        if len(raw)>MAX_BYTES:raise ValueError('oversize')
        value=json.loads(raw)
        validate_snapshot(value)
        return value
    except (InvalidToken,ValueError,TypeError):
        raise BackupError('Staging snapshot authentication failed') from None


def integer(value):
    if isinstance(value,dict) and len(value)==1 and next(iter(value)) in {'$numberInt','$numberLong'}:
        value=next(iter(value.values()))
        if not isinstance(value,str) or not value.isdecimal() or len(value)>19:
            raise BackupError('Invalid snapshot version')
        value=int(value)
    if type(value) is not int or value<0 or value>=2**63-1:
        raise BackupError('Invalid snapshot version')
    return value


def quarantine_restore(value):
    """Restoration never revives a session, password or recovery proof.

    UUID/product bindings survive; accounts require a separate ownership review
    and new credentials before any later reactivation.
    """
    validate_snapshot(value)
    restored=copy.deepcopy(value)
    restored['collections']['sessions']=[]
    restored['collections']['staging_cka_tokens']=[]
    for row in restored['collections']['pending_accounts']:
        row['state']='restore-review'
        row['credentials_disabled']=True
        # Restored accounts must not recover platform privileges implicitly.
        row['role']='user'
        for field in ('credential_hash','password_hash','recovery_digest'):
            row.pop(field,None)
        for field in ('session_version','credential_version'):
            row[field]={'$numberLong':str(integer(row.get(field,0))+1)}
    return restored


def export_script(root_password):
    return _snapshot_export_script('identity_root', root_password)


def atlas_export_script(username, password):
    """Build a bounded export for a dedicated Atlas backup principal.

    Only send the returned script over an isolated process's standard input.
    Never put its credentials in a URI, argv, environment, logs or artifacts.
    """
    _validate_atlas_operator(username,password)
    return _snapshot_export_script(username,password)


def _validate_atlas_operator(username,password):
    if (not isinstance(username,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{2,63}',username)
            or username == 'identity_root' or not isinstance(password,str)
            or not 16 <= len(password) <= 256 or any(ord(c) < 32 for c in password)):
        raise BackupError('Invalid Atlas operator credential')


def _snapshot_export_script(username,password):
    return 'const backupUser='+json.dumps(username)+';\nconst backupPassword='+json.dumps(password)+';\n'+'''
const admin=db.getSiblingDB('admin');
const auth=admin.auth(backupUser,backupPassword);
if (!(auth === true || auth === 1 || auth.ok === 1)) throw new Error('backup authentication denied');
const session=db.getMongo().startSession();
session.startTransaction({readConcern:{level:'snapshot'}});
try {
 const stage=session.getDatabase('shadowops_identity_staging');
 const collections={};
 for (const name of ['pending_accounts','sessions','staging_cka_tokens','admin_inventory_audit','staging_application_access_history']) {
  const rows=stage.getCollection(name).find({}).limit(10001).toArray();
  if (rows.length>10000) throw new Error('pilot snapshot bound exceeded');
  collections[name]=EJSON.serialize(rows,{relaxed:false});
 }
 session.commitTransaction();
 print(JSON.stringify({schema:2,environment:'staging',database:'shadowops_identity_staging',collections}));
} catch (error) { try { session.abortTransaction(); } catch (_) {} throw error; }
finally { session.endSession(); }
'''


def restore_script(root_password,value):
    return _quarantine_restore_script('identity_root',root_password,value)


def atlas_restore_script(username,password,value):
    """Restore to an empty Atlas staging database using a dedicated operator."""
    _validate_atlas_operator(username,password)
    return _quarantine_restore_script(username,password,value)


def _quarantine_restore_script(username,password,value):
    # Only a quarantine plan is sent to Mongo; live credentials never reappear.
    restored=quarantine_restore(value)
    return 'const restoreUser='+json.dumps(username)+';\nconst restorePassword='+json.dumps(password)+';\nconst snapshot='+json.dumps(restored)+';\n'+'''
const auth=db.getSiblingDB('admin').auth(restoreUser,restorePassword);
if (!(auth === true || auth === 1 || auth.ok === 1)) throw new Error('restore authentication denied');
const session=db.getMongo().startSession();
try {
 session.withTransaction(()=>{
  const stage=session.getDatabase('shadowops_identity_staging');
  for (const name of ['pending_accounts','sessions','staging_cka_tokens','admin_inventory_audit','staging_application_access_history']) {
   if (stage.getCollection(name).findOne({}) !== null) throw new Error('restore refuses nonempty destination');
  }
  const rows=EJSON.deserialize(snapshot.collections.pending_accounts,{relaxed:false});
  if (rows.length) stage.getCollection('pending_accounts').insertMany(rows);
  for (const name of ['admin_inventory_audit','staging_application_access_history']) {
   const saved=EJSON.deserialize(snapshot.collections[name] || [],{relaxed:false});
   if (saved.length) stage.getCollection(name).insertMany(saved);
  }
 },{readConcern:{level:'snapshot'},writeConcern:{w:'majority'}});
 print('IDENTITY_STAGING_QUARANTINE_RESTORE_OK');
} finally { session.endSession(); }
'''
