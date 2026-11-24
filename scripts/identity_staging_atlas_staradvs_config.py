"""Derive a separate Star Adventures Atlas configuration, without I/O.

The caller must establish the actual active Atlas config and Vault custody.
This pure function never changes either input or authorizes a release.
"""
from copy import deepcopy
import re

from identity_staging_atlas import _connection, AtlasConfigurationError

AUDIENCE = "staradvs"
DATABASE_FIELDS = frozenset({
    "mongo_uri", "admin_inventory_mongo_uri", "mongo_ca_pem", "mongo_privilege_mode",
})
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")


class StarAdvsConfigBlocked(ValueError):
    pass


def _consumers(config):
    values = config.get("consumers")
    if (not isinstance(values, dict) or not values
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not PROOF.fullmatch(v) for k, v in values.items())
            or len(set(values.values())) != len(values)):
        raise StarAdvsConfigBlocked("Invalid independent consumer credentials")
    return values


def candidate_config(active, vault_service):
    """Preserve the actual active Atlas config; add only its missing StarAdvs proof."""
    if any(not isinstance(x, dict) or x.get("environment") != "staging"
           for x in (active, vault_service)):
        raise StarAdvsConfigBlocked("Staging custody required")
    old, new = _consumers(active), _consumers(vault_service)
    if AUDIENCE in old or set(new) != set(old) | {AUDIENCE} or any(
            new[k] != v for k, v in old.items()):
        raise StarAdvsConfigBlocked("Vault is not an exact single-consumer extension")
    if "snooker" not in old:
        raise StarAdvsConfigBlocked("Current Snooker custody is not established")
    ignored = DATABASE_FIELDS | {"consumers"}
    if ({k: v for k, v in active.items() if k not in ignored}
            != {k: v for k, v in vault_service.items() if k not in ignored}):
        raise StarAdvsConfigBlocked("Non-database custody changed")
    if active.get("mongo_ca_pem") != "" or active.get("mongo_privilege_mode") != "database-scoped":
        raise StarAdvsConfigBlocked("Database-scoped Atlas custody required")
    try:
        app_host, app_user = _connection(active.get("mongo_uri"))
        inv_host, inv_user = _connection(active.get("admin_inventory_mongo_uri"))
    except AtlasConfigurationError:
        raise StarAdvsConfigBlocked("Invalid Atlas connection custody") from None
    if app_host != inv_host or app_user == inv_user:
        raise StarAdvsConfigBlocked("Independent same-cluster Atlas users required")
    result = deepcopy(active)
    result["consumers"][AUDIENCE] = new[AUDIENCE]
    return result
