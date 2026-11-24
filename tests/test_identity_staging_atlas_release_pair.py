"""Offline Atlas release pair tests: no Docker, network, or secret access."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from identity_staging_atlas_release_pair import (
    live_release, guarded_release, ReleaseCheckpoint, check_pair, SOURCE,
)
from identity_staging_atlas_transition import (
    AtlasTransitionBlocked, TransitionCheckpoint, CONFIG, SNOOKER_CONFIG,
    STARADVS_CONFIG, IMAGE, PROJECT, TARGET, NETWORKS,
)

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


def pair(config, digest=OLD, sha="c" * 40):
    return {"digest": digest, "source_sha": sha, "config": config}


def inspect(config):
    return [{
        "Config": {"Image": IMAGE + OLD, "Labels": {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": "identity",
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": "c" * 40}},
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "HostConfig": {"PortBindings": None},
        "NetworkSettings": {"Networks": {k: {} for k in NETWORKS}},
        "Mounts": [{"Destination": TARGET, "Source": config, "RW": False, "Type": "bind"}],
    }]


class ReleasePairTests(unittest.TestCase):
    def test_actual_mount_is_preserved_for_all_fixed_configs(self):
        for config in (CONFIG, SNOOKER_CONFIG, STARADVS_CONFIG):
            self.assertEqual(live_release(inspect(config)), pair(config))

    def test_reject_ambiguous_untrusted_or_unhealthy_mount(self):
        for change in (
            lambda r: r[0]["Mounts"][0].update(Source="/tmp/foreign"),
            lambda r: r[0]["Mounts"][0].update(RW=True),
            lambda r: r[0]["Mounts"].append(deepcopy(r[0]["Mounts"][0])),
            lambda r: r[0]["State"]["Health"].update(Status="unhealthy"),
            lambda r: r[0]["Config"]["Labels"].update(
                {"org.opencontainers.image.revision": "latest"}),
            lambda r: r[0]["Config"]["Labels"].update(
                {"org.opencontainers.image.source": "foreign"}),
        ):
            rows = inspect(SNOOKER_CONFIG)
            change(rows)
            with self.assertRaises(AtlasTransitionBlocked):
                live_release(rows)

    def test_config_only_release_rolls_back_exact_previous_mount(self):
        previous, candidate = pair(SNOOKER_CONFIG), pair(STARADVS_CONFIG)
        with tempfile.TemporaryDirectory() as tmp:
            journal = ReleaseCheckpoint(tmp, expected_uid=os.getuid())
            changes = []
            with self.assertRaisesRegex(AtlasTransitionBlocked, "previous release verified"):
                guarded_release(previous, candidate, journal=journal,
                                activate=changes.append, verify=lambda p: p == previous)
            self.assertEqual(changes, [candidate, previous])
            self.assertFalse(journal.path.exists())

    def test_pending_record_binds_both_images_and_configs(self):
        previous, candidate = pair(SNOOKER_CONFIG), pair(STARADVS_CONFIG, NEW, "d" * 40)
        with tempfile.TemporaryDirectory() as tmp:
            journal = ReleaseCheckpoint(tmp, expected_uid=os.getuid())
            with self.assertRaisesRegex(AtlasTransitionBlocked, "checkpoint retained"):
                guarded_release(previous, candidate, journal=journal,
                                activate=lambda _: None, verify=lambda _: False)
            self.assertEqual(json.loads(journal.path.read_text()),
                             {"previous": previous, "candidate": candidate})
            legacy = TransitionCheckpoint(tmp, expected_uid=os.getuid())
            with self.assertRaises(AtlasTransitionBlocked):
                legacy.begin(OLD, NEW)
            with self.assertRaises(AtlasTransitionBlocked):
                legacy.clear(OLD, NEW)
            with self.assertRaises(AtlasTransitionBlocked):
                journal.clear(pair(CONFIG), candidate)
            self.assertTrue(journal.path.exists())
            journal.clear(previous, candidate)

    def test_success_clears_checkpoint_and_same_digest_different_sha_blocks(self):
        previous, candidate = pair(SNOOKER_CONFIG), pair(STARADVS_CONFIG)
        with tempfile.TemporaryDirectory() as tmp:
            journal = ReleaseCheckpoint(tmp, expected_uid=os.getuid())
            changes = []
            guarded_release(previous, candidate, journal=journal,
                            activate=changes.append, verify=lambda p: p == candidate)
            self.assertEqual(changes, [candidate])
            self.assertFalse(journal.path.exists())
        with self.assertRaises(AtlasTransitionBlocked):
            check_pair(previous, pair(STARADVS_CONFIG, sha="d" * 40))
        with self.assertRaises(AtlasTransitionBlocked):
            check_pair(previous, pair(CONFIG))
        with self.assertRaises(AtlasTransitionBlocked):
            check_pair(previous, {**candidate, "config": "/tmp/foreign"})


if __name__ == "__main__":
    unittest.main()
