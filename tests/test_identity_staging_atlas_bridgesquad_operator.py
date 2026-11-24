"""Offline Bridge Squad Atlas activation/rollback and fixed entrypoint; never call real Docker."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


op = load("bridgesquad_operator", "host/identity-atlas-staging-staradvs.py")
entry = load("bridgesquad_entry", "host/identity-atlas-staging-bridgesquad.py")
from identity_staging_atlas_transition import AtlasTransitionBlocked

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


class Fake:
    def __init__(self, previous, candidate, fail=False):
        self.previous, self.candidate = previous, candidate
        self.active, self.changes, self.fail = previous, [], fail

    def run(self, args, *, digest=None, config_source=None, timeout=180):
        if args[:3] == ["docker", "image", "inspect"]:
            return "local"
        if args[:2] == ["docker", "compose"] and "config" in args:
            return "{}"
        if args[:2] == ["docker", "compose"] and "up" in args:
            self.active = self.candidate if config_source == self.candidate["config"] else self.previous
            assert digest == self.active["digest"]
            self.changes.append(self.active)
            return ""
        if args[0] == "curl":
            app = args[-1].split("=")[-1]
            if self.fail and self.active == self.candidate and app == "bridgesquad":
                return "denied"
            return "https://staging." + op.ORIGINS[app] + ".shadowops.dpdns.org/?shadowops=central"
        raise AssertionError("Unexpected command")


class OperatorTests(unittest.TestCase):
    def test_activation_and_rollback_from_each_allowed_previous_config(self):
        for prev_config, old in ((op.SNOOKER_CONFIG, {"snooker"}),
                                 (op.STARADVS_CONFIG, {"snooker", "staradvs"})):
            previous = {"digest": OLD, "source_sha": "c" * 40, "config": prev_config}
            candidate = {"digest": NEW, "source_sha": "d" * 40, "config": op.BRIDGESQUAD_CONFIG}
            for fail in (False, True):
                fake = Fake(previous, candidate, fail)
                with tempfile.TemporaryDirectory() as tmp, \
                        patch.object(op, "observe", side_effect=lambda _: fake.active), \
                        patch.object(op, "validate_atlas_compose"):
                    journal = op.ReleaseCheckpoint(tmp, expected_uid=os.getuid())
                    call = lambda: op.activate_release(
                        previous, candidate, old_consumers=old,
                        new_consumers=old | {"bridgesquad"}, run=fake.run,
                        public_sha=lambda _: fake.active["source_sha"], journal=journal)
                    if fail:
                        with self.assertRaisesRegex(AtlasTransitionBlocked, "previous release verified"):
                            call()
                        self.assertEqual(fake.changes, [candidate, previous])
                    else:
                        call()
                        self.assertEqual(fake.changes, [candidate])
                    self.assertFalse(journal.path.exists())

    def test_self_transition_rejected(self):
        same = {"digest": OLD, "source_sha": "c" * 40, "config": op.BRIDGESQUAD_CONFIG}
        with self.assertRaises(AtlasTransitionBlocked):
            op.check_pair(same, dict(same, digest=NEW, source_sha="d" * 40))

    def test_unknown_audience_rejected_before_host_access(self):
        def never(*_a, **_k):
            raise AssertionError("host accessed")
        with self.assertRaises(op.ReleaseBlocked):
            op.update("ocid1.vault.oc1.synthetic", NEW, "d" * 40, load=never,
                      check_shared=never, audience="snooker")

    def test_entrypoint_fixes_audience_and_requires_root(self):
        calls = []
        class Fake:
            def update(self, *args, **kwargs):
                calls.append((args, kwargs))
                return "IDENTITY_ATLAS_BRIDGESQUAD_DEPLOY_OK"
        argv = ["x", "deploy", "ocid1.vault.oc1.synthetic", NEW, "d" * 40]
        self.assertEqual(entry.main(argv, euid=lambda: 1000, loader=Fake), 1)
        self.assertEqual(entry.main(["x", "deploy-staradvs"] + argv[2:], euid=lambda: 0, loader=Fake), 1)
        self.assertEqual(calls, [])
        self.assertEqual(entry.main(argv, euid=lambda: 0, loader=Fake), 0)
        self.assertEqual(calls, [(tuple(argv[2:]), {"audience": "bridgesquad"})])

    def test_install_does_not_delegate_new_root_operator(self):
        installer = (ROOT / "host/install-identity-staging.sh").read_text()
        for item in ("host/identity-atlas-staging-bridgesquad.py",
                     "identity_staging_atlas_bridgesquad_config",
                     "identity_staging_atlas_extension"):
            self.assertIn(item, installer)
        self.assertNotIn("shadowops-identity-atlas-bridgesquad",
                         (ROOT / "host/identity-staging.sudoers").read_text())


if __name__ == "__main__":
    unittest.main()
