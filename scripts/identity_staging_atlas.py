"""Build an opt-in staging service config for Atlas without opening a connection.

This module does not read Vault, provision a user, print secrets, deploy, migrate
or access a database. The callers must obtain an independently provisioned Atlas
application credential and inventory credential through approved custody.
"""
from copy import deepcopy
from urllib.parse import parse_qsl, unquote, urlsplit

DATABASE = 'shadowops_identity_staging'

class AtlasConfigurationError(ValueError):
    pass

def _connection(uri):
    try:
        if not isinstance(uri, str) or len(uri) > 4096 or any(ord(c) < 32 for c in uri):
            raise ValueError()
        u = urlsplit(uri)
        if (u.scheme != 'mongodb+srv' or not u.hostname or u.port is not None or
            not u.username or not u.password or u.fragment or u.path != '/' + DATABASE):
            raise ValueError()
        # Do not permit ambiguous hostnames or non-Atlas endpoints in this
        # explicit Atlas handoff. DNS and certificates are validated by the driver.
        host = u.hostname.lower()
        if not host.endswith('.mongodb.net') or host == 'mongodb.net' or ',' in host:
            raise ValueError()
        pairs = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
        allowed = {'tls', 'authsource', 'retrywrites', 'w', 'appname'}
        params = {}
        for key, value in pairs:
            key = key.lower()
            if key not in allowed or key in params or not value:
                raise ValueError()
            params[key] = value
        if params.get('tls') != 'true' or params.get('authsource') != 'admin':
            raise ValueError()
        return host, unquote(u.username, errors="strict")
    except (TypeError, ValueError, UnicodeError):
        raise AtlasConfigurationError('Invalid staging Atlas configuration') from None

def atlas_service_config(local_config, application_uri, inventory_uri):
    """Return a copy bound to one Atlas cluster and two independent users."""
    if not isinstance(local_config, dict) or local_config.get('environment') != 'staging':
        raise AtlasConfigurationError('Invalid staging Atlas configuration')
    app_host, app_user = _connection(application_uri)
    inventory_host, inventory_user = _connection(inventory_uri)
    if app_host != inventory_host or app_user == inventory_user:
        raise AtlasConfigurationError('Invalid staging Atlas configuration')
    result = deepcopy(local_config)
    result['mongo_uri'] = application_uri
    result['admin_inventory_mongo_uri'] = inventory_uri
    # Empty roots instruct the Go TLS client to use its system trust store.
    result['mongo_ca_pem'] = ''
    return result
