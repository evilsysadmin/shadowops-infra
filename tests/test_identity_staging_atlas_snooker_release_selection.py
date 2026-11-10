"""Offline-only: candidate Snooker config and old-image rollback stay isolated."""
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from identity_staging_atlas_policy import (
    validate_atlas_compose, AtlasPolicyError, LEGACY_CONFIG, SNOOKER_CONFIG,
)
from identity_staging_atlas_transition import (
    image_from_atlas_container, AtlasTransitionBlocked, IMAGE, PROJECT,
)
from test_identity_staging_atlas_release import release, OLD, NEW, OLD_SHA, NEW_SHA, inspected
from test_identity_staging_atlas_snooker_config import fixture
from identity_staging_atlas_snooker_config import candidate_config

def compose_fixture(image, source):
    return {
        "name": PROJECT,
        "networks": {
            "origin": {"name": PROJECT + "-origin", "internal": True},
            "atlas-egress": {"name": PROJECT + "-atlas-egress"},
            "tunnel-egress": {"name": PROJECT + "-tunnel-egress"},
        },
        "services": {
            "identity": {
                "image": IMAGE + image, "platform": "linux/arm64",
                "user": "65532:65532", "read_only": True, "init": True,
                "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                "restart": "unless-stopped", "pids_limit": 128,
                "mem_limit": 268435456, "cpus": 0.75,
                "networks": {
                    "origin": {"aliases": ["id-staging.shadowops.dpdns.org"]},
                    "atlas-egress": {},
                },
                "volumes": [{"type": "bind", "source": source,
                             "target": "/run/secrets/identity-staging.json",
                             "read_only": True}],
            },
            "identity-tunnel": {
                "image": "cloudflare/cloudflared@sha256:"
                    "b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4",
                "platform": "linux/arm64", "user": "65532:65532",
                "read_only": True, "init": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "restart": "unless-stopped", "pids_limit": 64,
                "mem_limit": 134217728, "cpus": 0.25,
                "networks": {"origin": {}, "tunnel-egress": {}},
                "command": ["tunnel", "--no-autoupdate", "--metrics",
                            "127.0.0.1:20241", "run"],
                "environment": {"TUNNEL_TOKEN": "synthetic-no-secret"},
                "depends_on": {"identity": {"condition": "service_healthy"}},
                "volumes": [{"type": "bind", "source": "/etc/shadowops/identity-staging/ca.pem",
                             "target": "/run/identity/ca.pem", "read_only": True}],
            },
        },
    }


class DualConfigPolicyTests(unittest.TestCase):
    def test_only_exact_source_for_selected_image_passes_compose_policy(self):
        validate_atlas_compose(compose_fixture(OLD, LEGACY_CONFIG), OLD)
        validate_atlas_compose(compose_fixture(NEW, SNOOKER_CONFIG), NEW,
                               config_source=SNOOKER_CONFIG)
        for image, source, expected in (
            (NEW, LEGACY_CONFIG, SNOOKER_CONFIG),
            (OLD, SNOOKER_CONFIG, LEGACY_CONFIG),
            (NEW, "/tmp/secret.json", SNOOKER_CONFIG),
        ):
            with self.subTest(source=source), self.assertRaises(AtlasPolicyError):
                validate_atlas_compose(compose_fixture(image, source),
                                       image, config_source=expected)
        with self.assertRaises(AtlasPolicyError):
            validate_atlas_compose(compose_fixture(NEW, SNOOKER_CONFIG), NEW,
                                   config_source="/tmp/secret.json")

    def test_inspect_refuses_wrong_bind_source_for_previous_and_candidate(self):
        self.assertEqual(image_from_atlas_container(inspected(OLD, OLD_SHA)), OLD)
        self.assertEqual(image_from_atlas_container(
            inspected(NEW, NEW_SHA), config_source=SNOOKER_CONFIG), NEW)
        with self.assertRaises(AtlasTransitionBlocked):
            image_from_atlas_container(inspected(NEW, NEW_SHA))
        with self.assertRaises(AtlasTransitionBlocked):
            image_from_atlas_container(inspected(OLD, OLD_SHA),
                                       config_source=SNOOKER_CONFIG)
        with self.assertRaises(AtlasTransitionBlocked):
            image_from_atlas_container(inspected(NEW, NEW_SHA),
                                       config_source="/tmp/secret.json")

    def test_release_subprocess_accepts_only_two_fixed_sources_and_no_env_leak(self):
        calls = []
        def run(args, **kwargs):
            calls.append(kwargs.get("env"))
            return SimpleNamespace(returncode=0, stdout="")
        with patch.object(release.subprocess, "run", side_effect=run):
            release.run(["docker", "compose", "config"], digest=NEW,
                        config_source=SNOOKER_CONFIG)
            self.assertEqual(calls[0]["IDENTITY_ATLAS_SERVICE_CONFIG"], SNOOKER_CONFIG)
            self.assertEqual(calls[0]["IDENTITY_IMAGE_DIGEST"], NEW)
            self.assertEqual(set(calls[0]), {"PATH", "NO_PROXY",
                                              "IDENTITY_IMAGE_DIGEST",
                                              "IDENTITY_ATLAS_SERVICE_CONFIG"})
            with self.assertRaises(release.AtlasReleaseBlocked):
                release.run(["docker", "compose", "config"], digest=NEW,
                            config_source="/tmp/private.json")
            self.assertEqual(len(calls), 1, "bad source refused before subprocess")


class IsolatedCandidateAdmissionTests(unittest.TestCase):
    def test_requires_only_snooker_extension_while_previous_config_unchanged(self):
        local, atlas, vault = fixture()
        candidate = candidate_config(local, atlas, vault)
        entries = {"service.json": local, "atlas-service.json": atlas,
                   "atlas-snooker-service.json": candidate}
        reads = []
        prep = SimpleNamespace(
            trusted_dir=lambda path: None,
            load_private=lambda path, uid: (
                reads.append((path.name, uid)) or deepcopy(entries[path.name])),
        )
        mode = SimpleNamespace(st_mode=stat.S_IFREG | 0o400,
                               st_uid=65532, st_size=1024)
        with patch.object(release, "load_operator", return_value=prep), patch.object(
                release.Path, "lstat", return_value=mode):
            release.require_isolated_config()
            self.assertEqual([name for name, _ in reads], [
                "service.json", "atlas-service.json", "atlas-snooker-service.json"])
            self.assertTrue(all(uid == 65532 for _, uid in reads))
            tampered = deepcopy(candidate)
            tampered["signing_seed"] = "unexpected-rotation"
            entries["atlas-snooker-service.json"] = tampered
            with self.assertRaises(release.AtlasReleaseBlocked):
                release.require_isolated_config()
            entries["atlas-snooker-service.json"] = candidate
        self.assertEqual(atlas["consumers"], local["consumers"],
                         "the old rollback config must stay unchanged")

    def test_missing_candidate_and_wrong_owner_refuse_before_docker(self):
        prepared = SimpleNamespace(trusted_dir=lambda root: None, load_private=lambda *a: {})
        with patch.object(release, "load_operator", return_value=prepared), patch.object(
                release.Path, "lstat", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                release.require_isolated_config()
        bad = SimpleNamespace(st_mode=stat.S_IFREG | 0o644,
                              st_uid=65532, st_size=1024)
        with patch.object(release, "load_operator", return_value=prepared), patch.object(
                release.Path, "lstat", return_value=bad):
            with self.assertRaises(release.AtlasReleaseBlocked):
                release.require_isolated_config()


if __name__ == "__main__":
    unittest.main()
