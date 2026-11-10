"""Pure fail-closed derivation of a *separate* Snooker Atlas service config.

The old 34d5aa2 Identity image cannot recognize the Snooker audience. Never
alter its live atlas-service.json: it must remain usable by rollback.

The prospective candidate config only adds a proven independent Vault Snooker
service credential. Every other service setting, consumer credential, Atlas
connection, signing seed, inventory and TLS value must be unchanged.
"""
from copy import deepcopy

SN = "snooker"
SOURCE_TO_ATLAS = frozenset({
    "mongo_uri", "admin_inventory_mongo_uri", "mongo_ca_pem", "mongo_privilege_mode",
})


class SnookerConfigBlocked(ValueError):
    pass


def candidate_config(local, atlas, vault_service):
    if not all(isinstance(x, dict) for x in (local, atlas, vault_service)):
        raise SnookerConfigBlocked("Staging service configs required")
    if any(x.get("environment") != "staging" for x in (local, atlas, vault_service)):
        raise SnookerConfigBlocked("Wrong Identity environment")
    source = local.get("consumers")
    old = atlas.get("consumers")
    new = vault_service.get("consumers")
    if not all(isinstance(x, dict) and x for x in (source, old, new)):
        raise SnookerConfigBlocked("Invalid consumer maps")
    if SN in source or SN in old:
        raise SnookerConfigBlocked("Legacy config already enables Snooker")
    # The new Vault bundle must be a strict, single-consumer extension of
    # the old source; no key rotation or unrelated credentials can slip in.
    if set(new) != set(source) | {SN} or any(
        new.get(key) != value for key, value in source.items()
    ):
        raise SnookerConfigBlocked("Vault changed unrelated consumers")
    expected_local = deepcopy(vault_service)
    expected_local["consumers"].pop(SN)
    if expected_local != local:
        raise SnookerConfigBlocked("Vault and original service configuration diverge")
    original = {k: v for k, v in local.items() if k not in SOURCE_TO_ATLAS}
    atlas_comparable = {k: v for k, v in atlas.items() if k not in SOURCE_TO_ATLAS}
    if original != atlas_comparable or source != old:
        raise SnookerConfigBlocked("Atlas changed unrelated service settings")
    if (not isinstance(atlas.get("mongo_uri"), str)
            or not isinstance(atlas.get("admin_inventory_mongo_uri"), str)
            or atlas.get("mongo_ca_pem") != ""
            or atlas.get("mongo_privilege_mode") != "database-scoped"):
        raise SnookerConfigBlocked("Atlas custody not database scoped")
    candidate = deepcopy(atlas)
    candidate["consumers"] = deepcopy(new)
    return candidate
