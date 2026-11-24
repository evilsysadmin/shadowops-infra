"""Derive a separate Star Adventures Atlas configuration, without I/O.

The caller must establish the actual active Atlas config and Vault custody.
This pure function never changes either input or authorizes a release.
A pending, unreleased Bridge Squad proof in Vault is ignored, never copied.
"""
from identity_staging_atlas_extension import extend

AUDIENCE = "staradvs"


class StarAdvsConfigBlocked(ValueError):
    pass


def candidate_config(active, vault_service):
    """Preserve the actual active Atlas config; add only its missing StarAdvs proof."""
    return extend(active, vault_service, AUDIENCE, StarAdvsConfigBlocked)
