#!/usr/bin/env python3
"""Read-only metadata diagnosis for staged Snooker Identity consumer custody.

Runs as trusted root via the existing read-only SSH inspection transport.
No writes, no Vault access, no Docker commands, no secrets/credential hashes
or private paths in output. This DOES NOT enable a consumer or deploy Identity.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/etc/shadowops/identity-staging")
STATE = Path("/var/lib/shadowops/identity-staging")
ISSUER_CONFIG = ROOT / "service.json"
ATLAS_CONFIG = ROOT / "atlas-service.json"
CHECKPOINT = STATE / "atlas-deploy-pending.json"
ALLOWED = frozenset({"chess-studio", "chronicles", "cka-simulator", "football", "pawn-action", "snooker"})
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")


class AudienceAuditBlocked(Exception):
    def __init__(self, stage: str):
        self.stage = stage


def trusted_directory(path: Path, *, uid=0, private=False):
    for directory in (path, *path.parents):
        meta = directory.lstat()
        if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != uid or meta.st_mode & 0o022):
            raise AudienceAuditBlocked("paths")
    if private and path.stat().st_mode & 0o077:
        raise AudienceAuditBlocked("paths")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AudienceAuditBlocked("config")
        result[key] = value
    return result


def consumer_proofs(path: Path, *, owner=65532):
    meta = path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != owner or meta.st_mode & 0o077
            or not 0 < meta.st_size <= 131072):
        raise AudienceAuditBlocked("config")
    try:
        config = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, ValueError, UnicodeError, TypeError):
        raise AudienceAuditBlocked("config") from None
    if not isinstance(config, dict) or config.get("environment") != "staging":
        raise AudienceAuditBlocked("config")
    consumers = config.get("consumers")
    if (not isinstance(consumers, dict) or not consumers or not set(consumers) <= ALLOWED
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not PROOF.fullmatch(v) for k, v in consumers.items())
            or len(set(consumers.values())) != len(consumers)):
        raise AudienceAuditBlocked("config")
    return consumers


def evaluate(*, root=ROOT, state=STATE, root_uid=0, service_uid=65532):
    trusted_directory(root, uid=root_uid)
    trusted_directory(state, uid=root_uid, private=True)
    try:
        (state / CHECKPOINT.name).lstat()
    except FileNotFoundError:
        pass
    else:
        raise AudienceAuditBlocked("checkpoint")
    source = consumer_proofs(root / ISSUER_CONFIG.name, owner=service_uid)
    atlas = consumer_proofs(root / ATLAS_CONFIG.name, owner=service_uid)
    source_state = "present" if "snooker" in source else "absent"
    atlas_state = "present" if "snooker" in atlas else "absent"
    parity = "matching" if source == atlas else "different"
    return ("IDENTITY_ATLAS_SNOOKER_AUDIENCE_DIAG source=" + source_state
            + " atlas=" + atlas_state
            + " consumer_parity=" + parity
            + " checkpoint=absent writes=false")


def main():
    if sys.argv[1:] or os.geteuid() != 0:
        print("IDENTITY_ATLAS_SNOOKER_AUDIENCE_BLOCKED stage=authority")
        return 1
    try:
        print(evaluate())
        return 0
    except AudienceAuditBlocked as exc:
        print("IDENTITY_ATLAS_SNOOKER_AUDIENCE_BLOCKED stage=" + exc.stage)
        return 1
    except Exception:
        # No exception type/text, path, metadata, user or credential exposure.
        print("IDENTITY_ATLAS_SNOOKER_AUDIENCE_BLOCKED stage=unverified")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
