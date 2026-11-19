"""Production Compose must not become a staging bypass or public listener."""
from pathlib import Path
import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/identity_production_compose_preflight.py"
spec = importlib.util.spec_from_file_location("identity_production_compose_preflight", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
COMPOSE = (ROOT / "compose.identity.production.yaml").read_text()
GOOD_DIGEST = "sha256:" + "a" * 64

def mode_regular(*, owner=65532, mode=0o600, size=8192):
    class Result:
        st_mode = stat.S_IFREG | mode
        st_uid = owner
        st_size = size
    return Result()

def fake_lstat(**changes):
    def check(p):
        if str(p) == "/run/secrets/production.json":
            return mode_regular(**changes)
        return mode_regular(owner=0, mode=0o755)
    return check

class ProductionComposeTests(unittest.TestCase):
    def test_good_nonsecret_operator_bundle_preflight(self):
        module.validate(GOOD_DIGEST, "/run/secrets/production.json", lstat=fake_lstat())

    def test_reject_any_unpinned_or_noncanonical_digest(self):
        for bad in ("", "latest", "sha256:"+"a"*63, "sha256:"+"Z"*64,
                    "sha256:"+"a"*64+"garbage", "sha256:"+"a"*64+"\n"):
            with self.subTest(bad=bad):
                with self.assertRaises(module.Refused):
                    module.validate(bad, "/run/secrets/production.json", lstat=fake_lstat())

    def test_reject_wrong_owner_group_permissions_symlink_and_missing_file(self):
        for config in ({"owner": 0}, {"mode": 0o644}, {"mode": 0o640},
                       {"mode": 0o200}, {"size": 0}, {"size": 131073}):
            with self.subTest(config=config):
                with self.assertRaises(module.Refused):
                    module.validate(GOOD_DIGEST, "/run/secrets/production.json",
                                    lstat=fake_lstat(**config))
        def symlink(p):
            if str(p) == "/run/secrets":
                result = mode_regular()
                result.st_mode = stat.S_IFLNK | 0o777
                return result
            return fake_lstat()(p)
        with self.assertRaises(module.Refused):
            module.validate(GOOD_DIGEST, "/run/secrets/production.json", lstat=symlink)
        with self.assertRaises(module.Refused):
            module.validate(GOOD_DIGEST, "/run/secrets/missing.json",
                            lstat=lambda p: (_ for _ in ()).throw(FileNotFoundError()))

    def test_refuse_relative_path_and_no_flags(self):
        for p in ("bundle.json", "", "/", "/tmp/bad\x00path"):
            with self.subTest(path=p):
                with self.assertRaises(module.Refused):
                    module.validate(GOOD_DIGEST, p, lstat=fake_lstat())
        self.assertEqual(module.main([]), 2)

    def test_deployment_surface_must_remain_private(self):
        for required in (
            'profiles: ["production"]', "command: [\"serve-ready\"]",
            'host_ip: 127.0.0.1', 'published: "19443"',
            "read_only: true", "cap_drop: [ALL]", "privileged: false",
            "create_host_path: false", "restart: \"no\"",
            "identity-production-candidate@", 'user: "65532:65532"',
        ):
            self.assertIn(required, COMPOSE)
        for forbidden in ("staging", "latest", "0.0.0.0", "docker.sock",
                          "network_mode: host", "build:", "privileged: true",
                          "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL",
                          "SECRET_KEY", "SIGNING_SEED"):
            self.assertNotIn(forbidden, "\n".join(
                x for x in COMPOSE.splitlines() if not x.lstrip().startswith("#")))

if __name__ == "__main__":
    unittest.main()
