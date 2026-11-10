"""Offline-only tests: never reach live Atlas, Docker or public Identity."""
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = spec_from_file_location("atlas_release_candidate", ROOT / "host/identity-atlas-staging-deploy.py")
release = module_from_spec(spec)
spec.loader.exec_module(release)

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
OLD_SHA = "c" * 40
NEW_SHA = "d" * 40
ID = "e" * 64


def inspected(image, sha):
    return [{
        "Config": {"Image": release.IMAGE + image,
                   "Labels": {"com.docker.compose.project": release.PROJECT,
                              "com.docker.compose.service": "identity",
                              "org.opencontainers.image.source":
                              "https://github.com/evilsysadmin/shadowops-infra",
                              "org.opencontainers.image.revision": sha}},
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "HostConfig": {"PortBindings": None},
        "NetworkSettings": {"Networks": {
            release.PROJECT + "-origin": {},
            release.PROJECT + "-atlas-egress": {}}},
        "Mounts": [{"Source": release.CONFIG if image == OLD else release.SNOOKER_CONFIG,
                    "Destination": "/run/secrets/identity-staging.json",
                    "RW": False, "Type": "bind"}],
    }]


class Preflight:
    def trusted_paths(self):
        return None

    def execute(self, digest, sha, config_path=None):
        assert config_path == release.SNOOKER_CONFIG, "Candidate must preflight using isolated config"
        return "IDENTITY_ATLAS_PREFLIGHT_OK source_sha=" + sha + " digest=" + digest


class Backup:
    def private_config(self):
        return {}


class FakeRunner:
    def __init__(self, *, fail_candidate=False, fail_previous=False):
        self.active = OLD
        self.fail_candidate = fail_candidate
        self.fail_previous = fail_previous
        self.mutations = []
        self.config_paths = []

    def __call__(self, args, *, digest=None, config_source=None, timeout=180):
        if args[:3] == ["docker", "ps", "-aq"]:
            return ID + "\n"
        if args[:2] == ["docker", "inspect"]:
            sha = OLD_SHA if self.active == OLD else NEW_SHA
            return json.dumps(inspected(self.active, sha))
        if args[:2] == ["docker", "compose"] and "config" in args:
            self.config_paths.append((digest, config_source, "config"))
            assert config_source == (release.CONFIG if digest == OLD else release.SNOOKER_CONFIG)
            return "{}"
        if args[:2] == ["docker", "compose"] and "up" in args:
            self.config_paths.append((digest, config_source, "up"))
            assert config_source == (release.CONFIG if digest == OLD else release.SNOOKER_CONFIG)
            assert args[-1] == "identity"
            assert "--no-deps" in args and "--pull" in args
            self.mutations.append(digest)
            self.active = digest
            return ""
        if args[0] == "curl":
            if (self.active == NEW and self.fail_candidate) or (
                    self.active == OLD and self.fail_previous and self.mutations):
                raise release.AtlasReleaseBlocked("Synthetic HTTPS outage")
            if args[-1].endswith("/api/identity/release"):
                sha = OLD_SHA if self.active == OLD else NEW_SHA
                return json.dumps({"service": "shadowops-identity",
                                   "environment": "staging", "source_sha": sha})
            if args[-1].endswith("/login?app=snooker"):
                return "safe " + release.SNOOKER_CALLBACK if self.active == NEW else "unknown"
        raise AssertionError("Unexpected command")


class AtlasReleaseCandidateTests(unittest.TestCase):
    def execute(self, fake, *, candidate=NEW, source=NEW_SHA):
        with tempfile.TemporaryDirectory() as directory:
            journal = release.TransitionCheckpoint(directory, expected_uid=os.getuid())
            with patch.object(release, "root_file"), patch.object(
                release, "require_atlas_restore_evidence"
            ), patch.object(release, "validate_atlas_compose"), patch.object(
                release, "require_isolated_config"):
                try:
                    result = release.update(candidate, source, runner=fake,
                                            preflight=Preflight(), backup_operator=Backup(),
                                            check_shared=lambda: None, journal=journal)
                finally:
                    exists = journal.path.exists()
            return result if "result" in locals() else None, exists

    def test_pinned_candidate_replaces_only_identity_and_proves_public_sha_and_audience(self):
        fake = FakeRunner()
        receipt, pending = self.execute(fake)
        self.assertEqual(receipt, "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + NEW_SHA + " digest=" + NEW)
        self.assertEqual(fake.mutations, [NEW])
        self.assertIn((NEW, release.SNOOKER_CONFIG, "up"), fake.config_paths)
        self.assertIn((OLD, release.CONFIG, "config"), fake.config_paths)
        self.assertFalse(pending)

    def test_failed_candidate_rolls_back_before_success_receipt(self):
        fake = FakeRunner(fail_candidate=True)
        with self.assertRaisesRegex(release.AtlasTransitionBlocked, "previous release verified"):
            self.execute(fake)
        self.assertEqual(fake.mutations, [NEW, OLD])
        self.assertIn((NEW, release.SNOOKER_CONFIG, "up"), fake.config_paths)
        self.assertIn((OLD, release.CONFIG, "up"), fake.config_paths)
        self.assertEqual(fake.active, OLD)

    def test_unverified_rollback_keeps_durable_checkpoint(self):
        fake = FakeRunner(fail_candidate=True, fail_previous=True)
        with tempfile.TemporaryDirectory() as directory:
            journal = release.TransitionCheckpoint(directory, expected_uid=os.getuid())
            with patch.object(release, "root_file"), patch.object(
                release, "require_atlas_restore_evidence"
            ), patch.object(release, "validate_atlas_compose"), patch.object(
                release, "require_isolated_config"):
                with self.assertRaisesRegex(release.AtlasTransitionBlocked, "checkpoint retained"):
                    release.update(NEW, NEW_SHA, runner=fake, preflight=Preflight(),
                                   backup_operator=Backup(), check_shared=lambda: None,
                                   journal=journal)
            self.assertTrue(journal.path.exists())

    def test_missing_rehearsal_fails_before_docker_or_mutation(self):
        fake = FakeRunner()
        with patch.object(release, "root_file"), patch.object(
            release, "require_atlas_restore_evidence", side_effect=ValueError("unsafe")
        ):
            with self.assertRaises(ValueError):
                release.update(NEW, NEW_SHA, runner=fake, preflight=Preflight(),
                               backup_operator=Backup(), check_shared=lambda: None)
        self.assertEqual(fake.mutations, [])

    def test_invalid_image_and_same_digest_never_recreate(self):
        fake = FakeRunner()
        for digest, sha in (("latest", NEW_SHA), (NEW, "broken")):
            with self.subTest(digest=digest, sha=sha), self.assertRaises(release.AtlasReleaseBlocked):
                self.execute(fake, candidate=digest, source=sha)
        with self.assertRaisesRegex(release.AtlasReleaseBlocked, "No Atlas image change"):
            self.execute(fake, candidate=OLD, source=OLD_SHA)
        self.assertEqual(fake.mutations, [])

    def test_mismatched_live_release_stops_before_recreate(self):
        fake = FakeRunner()
        original = fake.__call__
        class Mismatch:
            def __call__(self, args, *, digest=None, config_source=None, timeout=180):
                if args[0] == "curl" and args[-1].endswith("/api/identity/release"):
                    return json.dumps({"service": "shadowops-identity",
                                       "environment": "staging", "source_sha": NEW_SHA})
                return original(args, digest=digest, config_source=config_source, timeout=timeout)
        with self.assertRaisesRegex(release.AtlasReleaseBlocked, "differs"):
            self.execute(Mismatch())
        self.assertEqual(fake.mutations, [])


if __name__ == "__main__":
    unittest.main()
