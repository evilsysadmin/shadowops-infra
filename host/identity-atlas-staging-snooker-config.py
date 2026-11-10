#!/opt/shadowops/oci-venv/bin/python -I
"""Root-only, explicit Snooker Atlas *candidate config* preparation.

This operation does NOT change the mounted legacy service or release Identity.
It copies only the verified Vault Snooker consumer into a NEW private config
whose fixed path can later be admitted by a separately reviewed release policy.
"""
import fcntl
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.path.insert(0, "/usr/local/lib/shadowops")
from identity_staging_atlas_lock import exclusive as atlas_lock
from identity_staging_atlas_snooker_config import (
    candidate_config, SnookerConfigBlocked,
)
from identity_staging_bundle import service_config
from shared_a1_host_guard import verify_shared_a1_containers

ROOT = Path("/etc/shadowops/identity-staging")
STATE = Path("/var/lib/shadowops/identity-staging")
CANDIDATE = ROOT / "atlas-snooker-service.json"
VAULT = re.compile(r"ocid1\.vault\.[A-Za-z0-9._-]{10,200}\Z")
PREVIOUS_SOURCE = "34d5aa2f4db3f522336a150266ac21f94d3ce95f"


class StageBlocked(ValueError):
    pass


def operator(name, path):
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    loaded = importlib.util.module_from_spec(spec)
    loader.exec_module(loaded)
    return loaded


def write_new(path, value, *, owner=65532):
    """Atomic creation only. Existing destination is NEVER replaced or removed."""
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > 131072:
        raise StageBlocked("Private candidate exceeds configuration bound")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".atlas-snooker-stage-")
    try:
        os.fchmod(fd, 0o400)
        os.fchown(fd, owner, owner)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link creation refuses an unexpected existing destination,
        # including a symlink. The old Atlas config is never a write target.
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage(vault, *, load=operator, verify_host=verify_shared_a1_containers):
    if not isinstance(vault, str) or not VAULT.fullmatch(vault):
        raise StageBlocked("Invalid fixed Vault request")
    with atlas_lock(STATE):
        prepare = load("atlas_prepare_snooker", "/usr/local/sbin/shadowops-identity-atlas-prepare")
        release = load("atlas_release_snooker", "/usr/local/sbin/shadowops-identity-atlas-deploy")
        local = load("local_identity_reader", "/usr/local/sbin/shadowops-identity-staging")
        prepare.trusted_dir(ROOT)
        release.root_file(STATE / "atlas-active", private=True)
        release.root_file(ROOT / "atlas-compose.yaml")
        if (STATE / "atlas-deploy-pending.json").exists() or (
                STATE / "atlas-deploy-pending.json").is_symlink():
            raise StageBlocked("Pending Atlas transition")
        verify_host()
        previous_digest, previous_sha = release.live_image(release.run)
        if previous_sha != PREVIOUS_SOURCE or release.public_release_sha(release.run) != previous_sha:
            raise StageBlocked("Legacy release does not match verified source")
        original = prepare.load_private(ROOT / "service.json", 65532)
        atlas = prepare.load_private(ROOT / "atlas-service.json", 65532)
        bundle = local.read_bundle(vault)
        if "snooker" not in bundle.get("consumers", {}):
            raise MissingVaultConsumer("Protected Snooker provision must complete first")
        # No local Mongo deployment, admin changes, key rotation or Atlas URI
        # regeneration; both old configs MUST remain byte-for-byte untouched.
        wanted = candidate_config(original, atlas, service_config(bundle))
        from identity_staging_atlas import _connection
        _connection(wanted["mongo_uri"])
        _connection(wanted["admin_inventory_mongo_uri"])
        if wanted["mongo_uri"] == wanted["admin_inventory_mongo_uri"]:
            raise StageBlocked("Atlas app and inventory credentials not independent")
        try:
            candidate = prepare.load_private(CANDIDATE, 65532)
        except FileNotFoundError:
            write_new(CANDIDATE, wanted)
            result = "created"
        else:
            if candidate != wanted:
                raise StageBlocked("Candidate config differs: explicit review required")
            result = "already-matching"
        if prepare.load_private(CANDIDATE, 65532) != wanted:
            raise StageBlocked("Candidate configuration not verified")
        if prepare.load_private(ROOT / "atlas-service.json", 65532) != atlas:
            raise StageBlocked("Legacy configuration unexpectedly changed")
        if prepare.load_private(ROOT / "service.json", 65532) != original:
            raise StageBlocked("Local source configuration unexpectedly changed")
        return ("IDENTITY_ATLAS_SNOOKER_CONFIG_STAGED result=" + result
                + " previous_config=unchanged local_source=unchanged"
                + " deploy=not-attempted")


class MissingVaultConsumer(StageBlocked):
    pass


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] != "stage"
            or not VAULT.fullmatch(sys.argv[2])):
        print("IDENTITY_ATLAS_SNOOKER_CONFIG_BLOCKED reason=authority", file=sys.stderr)
        return 1
    try:
        print(stage(sys.argv[2]))
        return 0
    except MissingVaultConsumer:
        print("IDENTITY_ATLAS_SNOOKER_CONFIG_BLOCKED reason=not-provisioned",
              file=sys.stderr)
        return 1
    except Exception:
        # Exception details, Atlas URLs, Vault IDs and private JSON are secret.
        print("IDENTITY_ATLAS_SNOOKER_CONFIG_BLOCKED reason=unverified",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
