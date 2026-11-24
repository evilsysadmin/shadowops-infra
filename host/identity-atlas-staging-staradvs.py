#!/opt/shadowops/oci-venv/bin/python -I
"""Explicit root-only single-audience Atlas release (Star Adventures or Bridge Squad).

No database or tunnel writes. Bridge Squad uses the thin
`identity-atlas-staging-bridgesquad.py` entrypoint over this same operator.

Requires independently admitted signed image and existing Vault custody.
Do not delegate this executable until the protected workflow admission is wired.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, "/usr/local/lib/shadowops")
from identity_staging_atlas_lock import exclusive
from identity_staging_atlas_admission import require_atlas_restore_evidence
from identity_staging_atlas_policy import validate_atlas_compose
from identity_staging_atlas_release_pair import (
    live_release, guarded_release, ReleaseCheckpoint, check_pair,
    CONFIG, SNOOKER_CONFIG, STARADVS_CONFIG, BRIDGESQUAD_CONFIG, DIGEST, SHA,
)
from identity_staging_atlas_staradvs_config import candidate_config
from identity_staging_atlas_bridgesquad_config import candidate_config as bridgesquad_candidate_config
from identity_staging_bundle import service_config
from shared_a1_host_guard import verify_shared_a1_containers
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec

ROOT = Path("/etc/shadowops/identity-staging")
STATE = Path("/var/lib/shadowops/identity-staging")
VAULT = re.compile(r"ocid1\.vault\.[A-Za-z0-9._-]{10,200}\Z")
PINNED_DIGEST = "sha256:baf6138eb8c37644800c7c913fba051e840ebb9ba13eaf92d92ef9a1712d0b4c"
PINNED_SHA = "349fa673f27d8a8abd5997f2fd55ab430f6db3dd"
PROJECT = "shadowops-identity-staging"
HOST = "https://id-staging.shadowops.dpdns.org"
ORIGINS = {
    "chess-studio": "chess-studio", "chronicles": "chronicles",
    "cka-simulator": "cka", "football": "football", "pawn-action": "pawnaction",
    "snooker": "snooker", "staradvs": "staradvs", "bridgesquad": "bridgesquad",
}
# Fixed per-audience candidate path, derivation and receipt; never client input.
TARGETS = {
    "staradvs": (STARADVS_CONFIG, candidate_config, "IDENTITY_ATLAS_STARADVS_DEPLOY_OK"),
    "bridgesquad": (BRIDGESQUAD_CONFIG, bridgesquad_candidate_config,
                    "IDENTITY_ATLAS_BRIDGESQUAD_DEPLOY_OK"),
}


class ReleaseBlocked(ValueError):
    pass


def operator(name, path):
    loader = SourceFileLoader(name, path)
    spec = spec_from_loader(name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def observe(run):
    ids = run(["docker", "ps", "-aq", "--filter",
               "label=com.docker.compose.project=" + PROJECT,
               "--filter", "label=com.docker.compose.service=identity"]).splitlines()
    if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", ids[0]):
        raise ReleaseBlocked("Ambiguous Identity container")
    return live_release(json.loads(run(["docker", "inspect", ids[0]])))


def callbacks_ready(run, consumers):
    for app in sorted(consumers):
        if app not in ORIGINS:
            return False
        html = run(["curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                    "--max-time", "12", "--header", "Cache-Control: no-cache",
                    HOST + "/login?app=" + app], timeout=18)
        if "https://staging." + ORIGINS[app] + ".shadowops.dpdns.org/?shadowops=central" not in html:
            return False
    return True


def activate_release(previous, candidate, *, old_consumers, new_consumers,
                     run, public_sha, journal):
    check_pair(previous, candidate)
    compose = ["docker", "compose", "--project-directory", str(ROOT),
               "-f", str(ROOT / "atlas-compose.yaml")]
    for item in (previous, candidate):
        normalized = json.loads(run(compose + ["config", "--format", "json"],
                                    digest=item["digest"], config_source=item["config"]))
        validate_atlas_compose(normalized, item["digest"], config_source=item["config"])
    # Both the preflighted candidate and previous image must be available
    # locally before entering the durable transition.
    for digest in {previous["digest"], candidate["digest"]}:
        run(["docker", "image", "inspect", "ghcr.io/evilsysadmin/shadowops-identity@" + digest,
             "--format", "{{.Id}}"])

    def activate(item):
        run(compose + ["up", "--detach", "--no-deps", "--wait",
                       "--wait-timeout", "150", "--no-build", "--pull", "never",
                       "--force-recreate", "identity"], digest=item["digest"],
            config_source=item["config"], timeout=195)

    def verify(item):
        return (observe(run) == item and public_sha(run) == item["source_sha"]
                and callbacks_ready(run, old_consumers if item == previous else new_consumers))

    guarded_release(previous, candidate, journal=journal, activate=activate, verify=verify)


def update(vault, digest, sha, *, load=operator, check_shared=verify_shared_a1_containers,
           audience="staradvs"):
    if audience not in TARGETS:
        raise ReleaseBlocked("Invalid fixed release request")
    target_config, derive, receipt = TARGETS[audience]
    if (not isinstance(vault, str) or not VAULT.fullmatch(vault)
            or digest != PINNED_DIGEST or sha != PINNED_SHA):
        raise ReleaseBlocked("Invalid fixed release request")
    with exclusive(STATE):
        prepare = load("staradvs_prepare", "/usr/local/sbin/shadowops-identity-atlas-prepare")
        release = load("staradvs_release", "/usr/local/sbin/shadowops-identity-atlas-deploy")
        preflight = load("staradvs_preflight", "/usr/local/sbin/shadowops-identity-atlas-preflight")
        backup = load("staradvs_backup", "/usr/local/sbin/shadowops-identity-atlas-backup")
        local = load("staradvs_vault", "/usr/local/sbin/shadowops-identity-staging")
        prepare.trusted_dir(ROOT)
        preflight.trusted_paths()
        release.root_file(STATE / "atlas-active", private=True)
        release.root_file(ROOT / "atlas-compose.yaml")
        journal = ReleaseCheckpoint(STATE)
        if journal.path.exists() or journal.path.is_symlink():
            raise ReleaseBlocked("Pending Atlas transition")
        require_atlas_restore_evidence(backup.private_config(), STATE)
        check_shared()
        previous = observe(release.run)
        candidate = {"digest": digest, "source_sha": sha, "config": target_config}
        check_pair(previous, candidate)
        if release.public_release_sha(release.run) != previous["source_sha"]:
            raise ReleaseBlocked("Public Identity source differs")
        active_path = Path(previous["config"])
        active = prepare.load_private(active_path, 65532)
        wanted = derive(active, service_config(local.read_bundle(vault)))
        if not callbacks_ready(release.run, active["consumers"]):
            raise ReleaseBlocked("Existing public consumer not proven")
        path = Path(target_config)
        try:
            existing = prepare.load_private(path, 65532)
        except FileNotFoundError:
            # Existing reviewed creation-only helper, never overwrites a config.
            prepare._write_new(path, wanted, 65532)
            existing = prepare.load_private(path, 65532)
        if existing != wanted or stat.S_IMODE(path.lstat().st_mode) != 0o400:
            raise ReleaseBlocked("Candidate custody differs")
        if preflight.execute(digest, sha, config_path=target_config) != (
                "IDENTITY_ATLAS_PREFLIGHT_OK source_sha=" + sha + " digest=" + digest):
            raise ReleaseBlocked("Candidate preflight not proven")
        if (observe(release.run) != previous or prepare.load_private(active_path, 65532) != active
                or prepare.load_private(path, 65532) != wanted):
            raise ReleaseBlocked("Release custody changed during preflight")
        # The old wrapper's run helper has a two-path allowlist. Use only its
        # fixed commands and a separate narrowly scoped Compose runner for the
        # new candidate path, without weakening legacy operator behavior.
        def run(args, *, digest=None, config_source=None, timeout=180):
            if config_source == target_config:
                import subprocess
                if (not DIGEST.fullmatch(digest or "") or args[:2] != ["docker", "compose"]):
                    raise ReleaseBlocked("Unexpected candidate Compose request")
                result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "NO_PROXY": "*",
                         "IDENTITY_IMAGE_DIGEST": digest,
                         "IDENTITY_ATLAS_SERVICE_CONFIG": target_config})
                if result.returncode or len(result.stdout) > 1048576:
                    raise ReleaseBlocked("Fixed candidate operation failed")
                return result.stdout
            return release.run(args, digest=digest, config_source=config_source, timeout=timeout)
        activate_release(previous, candidate, old_consumers=active["consumers"],
                         new_consumers=wanted["consumers"], run=run,
                         public_sha=release.public_release_sha, journal=journal)
    return receipt + " source_sha=" + sha + " digest=" + digest


def main():
    if os.geteuid() != 0 or len(sys.argv) != 5 or sys.argv[1] != "deploy":
        print("IDENTITY_ATLAS_STARADVS_BLOCKED reason=authority", file=sys.stderr)
        return 1
    try:
        print(update(sys.argv[2], sys.argv[3], sys.argv[4]))
        return 0
    except Exception:
        print("IDENTITY_ATLAS_STARADVS_BLOCKED reason=unverified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
