"""Offline-only Atlas transition contracts. No real Docker or credentials."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from identity_staging_atlas_transition import (
    AtlasTransitionBlocked, TransitionCheckpoint, guarded_transition,
    image_from_atlas_container, PROJECT, IMAGE, CONFIG, TARGET, NETWORKS,
)

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


def identity():
    return [{
        "Config": {"Image": IMAGE + OLD, "Labels": {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": "identity",
        }},
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "HostConfig": {"PortBindings": None},
        "NetworkSettings": {"Networks": {name: {} for name in NETWORKS}},
        "Mounts": [{"Source": CONFIG, "Destination": TARGET, "RW": False,
                    "Type": "bind"}],
    }]


class AtlasTransitionContracts(unittest.TestCase):
    def test_exact_live_atlas_container_yields_only_immutable_digest(self):
        self.assertEqual(image_from_atlas_container(identity()), OLD)

    def test_rejects_foreign_unhealthy_local_or_ambiguous_identity(self):
        for path, value in (
            (("Config", "Image"), IMAGE + "latest"),
            (("Config", "Image"), "other-registry/identity@" + OLD),
            (("Config", "Labels", "com.docker.compose.project"), "foreign"),
            (("Config", "Labels", "com.docker.compose.service"), "mongo"),
            (("State", "Status"), "restarting"),
            (("State", "Health", "Status"), "unhealthy"),
            (("HostConfig", "PortBindings"), {"9443/tcp": [{"HostPort": "9443"}]}),
            (("NetworkSettings", "Networks"), {PROJECT + "-origin": {}}),
            (("NetworkSettings", "Networks"), {name: {} for name in
                NETWORKS | {"foreign-network"}}),
            (("Mounts", 0, "Source"), "/etc/shadowops/identity-staging/service.json"),
            (("Mounts", 0, "Destination"), "/tmp/config"),
            (("Mounts", 0, "RW"), True),
            (("Mounts", 0, "Type"), "volume"),
        ):
            with self.subTest(path=path):
                case = identity()
                current = case[0]
                for segment in path[:-1]:
                    current = current[segment]
                current[path[-1]] = value
                with self.assertRaises(AtlasTransitionBlocked):
                    image_from_atlas_container(case)
        for rows in ([], None, identity() + identity(), [{}]):
            with self.subTest(rows=rows), self.assertRaises(AtlasTransitionBlocked):
                image_from_atlas_container(rows)
        case = identity()
        case[0]["Mounts"].append(dict(case[0]["Mounts"][0]))
        with self.assertRaises(AtlasTransitionBlocked):
            image_from_atlas_container(case)

    def test_journal_is_exclusive_and_contains_digests_only(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            checkpoint.begin(OLD, NEW)
            self.assertEqual(checkpoint.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(checkpoint.path.read_text(),
                             '{"previous":"' + OLD + '","candidate":"' + NEW + '"}')
            with self.assertRaises(AtlasTransitionBlocked):
                checkpoint.begin(OLD, NEW)
            with self.assertRaises(AtlasTransitionBlocked):
                checkpoint.clear(NEW, OLD)
            self.assertTrue(checkpoint.path.exists())
            checkpoint.clear(OLD, NEW)
            self.assertFalse(checkpoint.path.exists())

    def test_unsafe_journal_symlink_and_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            (Path(root) / "target").write_text("untouched")
            checkpoint.path.symlink_to(Path(root) / "target")
            with self.assertRaises(AtlasTransitionBlocked):
                checkpoint.begin(OLD, NEW)
            with self.assertRaises(AtlasTransitionBlocked):
                checkpoint.clear(OLD, NEW)
            self.assertEqual((Path(root) / "target").read_text(), "untouched")
            checkpoint.path.unlink()
            os.chmod(root, 0o770)
            with self.assertRaises(AtlasTransitionBlocked):
                checkpoint.begin(OLD, NEW)

    def test_invalid_or_identical_pair_never_activates(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            for pair in ((OLD, OLD), ("latest", NEW), (OLD, "sha256:bad")):
                changes = []
                with self.assertRaises(AtlasTransitionBlocked):
                    guarded_transition(*pair, journal=checkpoint,
                                       activate=changes.append, verify=lambda _: True)
                self.assertEqual(changes, [])
                self.assertFalse(checkpoint.path.exists())

    def test_verified_success_clears_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            changes = []
            guarded_transition(OLD, NEW, journal=checkpoint,
                               activate=changes.append, verify=lambda _: True)
            self.assertEqual(changes, [NEW])
            self.assertFalse(checkpoint.path.exists())

    def test_failed_candidate_rolls_back_and_retains_no_false_success(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            changes = []
            with self.assertRaisesRegex(AtlasTransitionBlocked, "previous release verified"):
                guarded_transition(OLD, NEW, journal=checkpoint,
                                   activate=changes.append, verify=lambda image: image == OLD)
            self.assertEqual(changes, [NEW, OLD])
            self.assertFalse(checkpoint.path.exists())

    def test_failed_rollback_preserves_checkpoint_and_denies_retries(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            changes = []
            with self.assertRaisesRegex(AtlasTransitionBlocked, "rollback unverified"):
                guarded_transition(OLD, NEW, journal=checkpoint,
                                   activate=changes.append, verify=lambda _: False)
            self.assertEqual(changes, [NEW, OLD])
            self.assertTrue(checkpoint.path.exists())
            with self.assertRaises(AtlasTransitionBlocked):
                guarded_transition(OLD, NEW, journal=checkpoint,
                                   activate=changes.append, verify=lambda _: True)
            self.assertEqual(changes, [NEW, OLD])

    def test_unexpected_private_activation_error_is_not_emitted(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = TransitionCheckpoint(root, expected_uid=os.getuid())
            attempts = []
            def activate(digest):
                attempts.append(digest)
                if digest == NEW:
                    raise RuntimeError("PRIVATE_ATLAS_PASSWORD")
            with self.assertRaises(AtlasTransitionBlocked) as result:
                guarded_transition(OLD, NEW, journal=checkpoint,
                                   activate=activate, verify=lambda _: True)
            self.assertNotIn("PRIVATE", str(result.exception))
            self.assertEqual(attempts, [NEW, OLD])
            self.assertFalse(checkpoint.path.exists())


if __name__ == "__main__":
    unittest.main()
