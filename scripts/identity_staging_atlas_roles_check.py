#!/usr/bin/env python3
"""Read-only connectivity and effective-role check for the staging Atlas users."""
import os
from identity_staging_atlas_provision import validate_inputs

DATABASE = 'shadowops_identity_staging'


def roles_valid(status, expected):
    info = status.get('authInfo', {})
    roles = info.get('authenticatedUserRoles', [])
    privileges = info.get('authenticatedUserPrivileges', [])
    return (len(info.get('authenticatedUsers', [])) == 1
            and roles == [{'role': expected, 'db': DATABASE}]
            and bool(privileges)
            and all(p.get('resource', {}).get('db') == DATABASE
                    and not p.get('resource', {}).get('anyResource')
                    and not p.get('resource', {}).get('cluster') for p in privileges))


def check(env):
    try:
        uris = validate_inputs(*(env.get('IDENTITY_ATLAS_STAGING_' + name + '_URI', '')
                                 for name in ('RUNTIME', 'INVENTORY', 'BACKUP')))
    except Exception:
        print('IDENTITY_ATLAS_CHECK_BLOCKED stage=input')
        return 1
    from pymongo import MongoClient
    for name, uri, role in zip(('runtime', 'inventory', 'backup'), uris, ('readWrite', 'readWrite', 'read')):
        try:
            with MongoClient(uri, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000) as client:
                status = client.admin.command('connectionStatus', showPrivileges=True)
                if not roles_valid(status, role):
                    print('IDENTITY_ATLAS_CHECK_BLOCKED stage=' + name + ' reason=roles')
                    return 1
                hello = client.admin.command('hello')
                if not hello.get('isWritablePrimary'):
                    print('IDENTITY_ATLAS_CHECK_BLOCKED stage=' + name + ' reason=topology')
                    return 1
        except Exception:
            # Driver errors can contain credentials: do not emit exception details.
            print('IDENTITY_ATLAS_CHECK_BLOCKED stage=' + name + ' reason=connection')
            return 1
        print('IDENTITY_ATLAS_CHECK_OK stage=' + name)
    return 0


if __name__ == '__main__':
    raise SystemExit(check(os.environ))
