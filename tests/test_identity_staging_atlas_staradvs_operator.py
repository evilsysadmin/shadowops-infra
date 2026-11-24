"""Offline StarAdvs activation and exact rollback; never call real Docker."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("staradvs_operator", ROOT / "host/identity-atlas-staging-staradvs.py")
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
from identity_staging_atlas_transition import AtlasTransitionBlocked

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
previous = {"digest": OLD, "source_sha": "c" * 40, "config": op.SNOOKER_CONFIG}
candidate = {"digest": NEW, "source_sha": "d" * 40, "config": op.STARADVS_CONFIG}


class Fake:
    def __init__(self, fail=False):
        self.active = previous
        self.changes = []
        self.fail = fail
    def run(self, args, *, digest=None, config_source=None, timeout=180):
        if args[:3] == ["docker", "image", "inspect"]:
            return "local"
        if args[:2] == ["docker", "compose"] and "config" in args:
            return "{}"
        if args[:2] == ["docker", "compose"] and "up" in args:
            assert args[-1] == "identity" and "--no-deps" in args and "--pull" in args
            self.active = candidate if config_source == op.STARADVS_CONFIG else previous
            assert digest == self.active["digest"]
            self.changes.append(self.active)
            return ""
        if args[0] == "curl":
            app = args[-1].split("=")[-1]
            if self.fail and self.active == candidate and app == "staradvs":
                return "denied"
            return "https://staging." + op.ORIGINS[app] + ".shadowops.dpdns.org/?shadowops=central"
        raise AssertionError("Unexpected command")


class OperatorTests(unittest.TestCase):
    def exercise(self, fake, journal):
        with patch.object(op, "observe", side_effect=lambda _: fake.active), patch.object(op, "validate_atlas_compose"):
            return op.activate_release(previous, candidate,
                old_consumers={"snooker", "football"}, new_consumers={"snooker", "football", "staradvs"},
                run=fake.run, public_sha=lambda _: fake.active["source_sha"], journal=journal)

    def test_activation_and_rollback_exact_pairs(self):
        for fail in (False, True):
            fake = Fake(fail)
            with tempfile.TemporaryDirectory() as tmp:
                journal = op.ReleaseCheckpoint(tmp, expected_uid=os.getuid())
                if fail:
                    with self.assertRaisesRegex(AtlasTransitionBlocked, "previous release verified"):
                        self.exercise(fake, journal)
                    self.assertEqual(fake.changes, [candidate, previous])
                else:
                    self.exercise(fake, journal)
                    self.assertEqual(fake.changes, [candidate])
                self.assertFalse(journal.path.exists())

    def test_unpinned_image_rejected_before_host_access(self):
        with self.assertRaises(op.ReleaseBlocked):
            op.update("ocid1.vault.oc1." + "v" * 24, OLD, "c" * 40,
                      load=lambda *a: self.fail("unexpected host access"))

    def test_foreign_callback_is_not_requested(self):
        self.assertFalse(op.callbacks_ready(lambda *a, **k: self.fail("unexpected request"), {"foreign"}))

    def test_install_delegates_only_pinned_root_operator(self):
        installer = (ROOT / "host/install-identity-staging.sh").read_text()
        self.assertIn("host/identity-atlas-staging-staradvs.py", installer)
        self.assertIn("identity_staging_atlas_release_pair", installer)
        from identity_staging_release import STARADVS_RELEASE_DIGEST, STARADVS_RELEASE_SHA
        sudoers = (ROOT / "host/identity-staging.sudoers").read_text()
        self.assertIn("shadowops-identity-atlas-staradvs deploy ocid1.vault.* "
                      + STARADVS_RELEASE_DIGEST.replace(":", "\\:") + " " + STARADVS_RELEASE_SHA, sudoers)
        self.assertNotIn("shadowops-identity-atlas-staradvs deploy *", sudoers)


if __name__ == "__main__":
    unittest.main()
