"""Atlas API role payloads for Identity staging; generates no users or secrets."""
import json
import sys

DATABASE = 'shadowops_identity_staging'
# These are the exact collections and actions required by verifyRuntimeRole
# and verifyAdminInventoryRole, plus separate snapshot and restore users. Access history is
# enabled and the optional
# short-lived recent-access view is disabled.
ROLE_ACTIONS = {
    'shadowops_identity_staging_runtime': {
        'pending_accounts': ('FIND', 'INSERT', 'UPDATE', 'CREATE_INDEX', 'LIST_INDEXES'),
        'sessions': ('FIND', 'INSERT', 'UPDATE', 'REMOVE', 'CREATE_INDEX', 'LIST_INDEXES'),
        'staging_cka_tokens': ('FIND', 'INSERT', 'UPDATE', 'CREATE_INDEX', 'LIST_INDEXES'),
        'staging_application_access_history': ('INSERT', 'UPDATE'),
    },
    'shadowops_identity_staging_backup': {
        'pending_accounts': ('FIND',),
        'sessions': ('FIND',),
        'staging_cka_tokens': ('FIND',),
        'admin_inventory_audit': ('FIND',),
        'staging_application_access_history': ('FIND',),
    },
    'shadowops_identity_staging_restore': {
        'pending_accounts': ('FIND', 'INSERT'),
        'sessions': ('FIND',),
        'staging_cka_tokens': ('FIND',),
        'admin_inventory_audit': ('FIND', 'INSERT'),
        'staging_application_access_history': ('FIND', 'INSERT'),
    },
    'shadowops_identity_staging_inventory': {
        'pending_accounts': ('FIND', 'UPDATE'),
        'sessions': ('FIND', 'UPDATE'),
        'admin_inventory_audit': ('INSERT',),
        'staging_application_access_history': ('FIND',),
    },
}

def payloads():
    roles = []
    for role, collections in ROLE_ACTIONS.items():
        grouped = {}
        for collection, actions in collections.items():
            for action in actions:
                grouped.setdefault(action, []).append({'db': DATABASE, 'collection': collection})
        roles.append({'roleName': role, 'actions': [
            {'action': action, 'resources': resources} for action, resources in sorted(grouped.items())
        ], 'inheritedRoles': []})
    return roles

def main():
    if len(sys.argv) != 1:
        print('No arguments accepted', file=sys.stderr)
        return 2
    print(json.dumps(payloads(), indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
