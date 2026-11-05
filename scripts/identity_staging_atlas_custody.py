"""Independent Atlas staging custody contract. No Vault access or I/O.

This contains only Atlas service credentials and its own backup key, never
local Mongo credentials. A future operator must store it in separate private
custody and explicitly install the derived configurations.
"""
import base64
import copy
import secrets
from urllib.parse import unquote, urlsplit

from identity_staging_atlas import AtlasConfigurationError, _connection, atlas_service_config, normalize_atlas_uri
from identity_staging_atlas_backup import validate_backup_config
from identity_staging_backup import BackupError


class AtlasCustodyError(ValueError):
    pass


def _parts(application_uri, inventory_uri, backup_uri, backup_key):
    try:
        app_host, app_user = _connection(application_uri)
        inventory_host, inventory_user = _connection(inventory_uri)
        backup_host, backup_user = _connection(backup_uri)
        if app_host != inventory_host or app_host != backup_host or len({app_user, inventory_user, backup_user}) != 3:
            raise ValueError()
        parsed = urlsplit(backup_uri)
        backup = {'environment': 'staging', 'host': backup_host, 'username': backup_user,
                  'password': unquote(parsed.password, errors='strict'), 'backup_key': backup_key}
        validate_backup_config(backup)
        return backup
    except (AtlasConfigurationError, BackupError, ValueError, TypeError, UnicodeError):
        raise AtlasCustodyError('Invalid independent Atlas staging custody') from None


def prepare_atlas_custody(existing, application_uri, inventory_uri, backup_uri):
    """Create once or preserve exactly; rotation must use a separate procedure."""
    if existing is None:
        backup_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    else:
        if (not isinstance(existing, dict) or set(existing) != {'schema','environment','application_uri','inventory_uri','backup_uri','backup_key'}
                or type(existing.get('schema')) is not int or existing['schema'] != 1 or existing['environment'] != 'staging'):
            raise AtlasCustodyError('Invalid independent Atlas staging custody')
        old_uris = (existing['application_uri'], existing['inventory_uri'], existing['backup_uri'])
        try:
            if tuple(map(normalize_atlas_uri, old_uris)) != tuple(map(normalize_atlas_uri, (application_uri, inventory_uri, backup_uri))):
                raise AtlasCustodyError('Atlas custody rotation requires a separate procedure')
        except AtlasConfigurationError:
            raise AtlasCustodyError('Invalid independent Atlas staging custody') from None
        _parts(*old_uris, existing['backup_key'])
        return copy.deepcopy(existing)
    _parts(application_uri, inventory_uri, backup_uri, backup_key)
    return {'schema': 1, 'environment': 'staging', 'application_uri': application_uri,
            'inventory_uri': inventory_uri, 'backup_uri': backup_uri, 'backup_key': backup_key}


def derived_configs(custody, local_service_config):
    """Return independent service and backup configs without mutating inputs."""
    if not isinstance(custody, dict):
        raise AtlasCustodyError('Invalid independent Atlas staging custody')
    try:
        checked = prepare_atlas_custody(custody, custody['application_uri'], custody['inventory_uri'], custody['backup_uri'])
        backup = _parts(checked['application_uri'], checked['inventory_uri'], checked['backup_uri'], checked['backup_key'])
        service = atlas_service_config(local_service_config, checked['application_uri'], checked['inventory_uri'])
        return service, copy.deepcopy(backup)
    except (KeyError, AtlasConfigurationError, ValueError, TypeError):
        raise AtlasCustodyError('Invalid independent Atlas staging custody') from None
