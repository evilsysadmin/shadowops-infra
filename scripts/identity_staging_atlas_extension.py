"""Pure single-audience extension of the active Atlas config, without I/O.

The caller must establish the actual active Atlas config and Vault custody.
Exactly one opt-in audience is added. Other reviewed opt-in audiences that
are already provisioned in Vault but not yet released are ignored (never
copied), so independent games can be released in either order.
"""
from copy import deepcopy
import re

from identity_staging_atlas import _connection, AtlasConfigurationError

OPT_IN = frozenset({"staradvs", "bridgesquad"})
DATABASE_FIELDS = frozenset({
    "mongo_uri", "admin_inventory_mongo_uri", "mongo_ca_pem", "mongo_privilege_mode",
})
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")


class ExtensionBlocked(ValueError):
    pass


def _consumers(config):
    values = config.get("consumers")
    if (not isinstance(values, dict) or not values
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not PROOF.fullmatch(v) for k, v in values.items())
            or len(set(values.values())) != len(values)):
        raise ExtensionBlocked("Invalid independent consumer credentials")
    return values


def extend(active, vault_service, audience, error=ExtensionBlocked):
    """Preserve the actual active Atlas config; add only `audience`'s proof."""
    if audience not in OPT_IN:
        raise error("Unknown opt-in audience")
    if any(not isinstance(x, dict) or x.get("environment") != "staging"
           for x in (active, vault_service)):
        raise error("Staging custody required")
    try:
        old, new = _consumers(active), _consumers(vault_service)
    except ExtensionBlocked:
        raise error("Invalid independent consumer credentials") from None
    pending = set(new) - set(old) - {audience}
    if (audience in old or audience not in new or not set(old) <= set(new)
            or not pending <= OPT_IN - {audience}
            or any(new[k] != v for k, v in old.items())):
        raise error("Vault is not an exact single-consumer extension")
    if "snooker" not in old:
        raise error("Current Snooker custody is not established")
    ignored = DATABASE_FIELDS | {"consumers"}
    if ({k: v for k, v in active.items() if k not in ignored}
            != {k: v for k, v in vault_service.items() if k not in ignored}):
        raise error("Non-database custody changed")
    if active.get("mongo_ca_pem") != "" or active.get("mongo_privilege_mode") != "database-scoped":
        raise error("Database-scoped Atlas custody required")
    try:
        app_host, app_user = _connection(active.get("mongo_uri"))
        inv_host, inv_user = _connection(active.get("admin_inventory_mongo_uri"))
    except AtlasConfigurationError:
        raise error("Invalid Atlas connection custody") from None
    if app_host != inv_host or app_user == inv_user:
        raise error("Independent same-cluster Atlas users required")
    result = deepcopy(active)
    result["consumers"][audience] = new[audience]
    return result
