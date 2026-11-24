"""Derive a separate Bridge Squad Atlas configuration, without I/O.

The caller must establish the actual active Atlas config and Vault custody.
This pure function never changes either input or authorizes a release.
A pending, unreleased Star Adventures proof in Vault is ignored, never copied.
"""
from identity_staging_atlas_extension import extend

AUDIENCE = "bridgesquad"


class BridgeSquadConfigBlocked(ValueError):
    pass


def candidate_config(active, vault_service):
    """Preserve the actual active Atlas config; add only its missing Bridge Squad proof."""
    return extend(active, vault_service, AUDIENCE, BridgeSquadConfigBlocked)
