"""Offline gates for the isolated Mongo production host candidate."""
import importlib.util
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import stat
import subprocess
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_prod_mongo_host", ROOT / "scripts/identity_production_mongo_host.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class MongoHostContractTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / "compose.identity.production-mongo.yaml").read_text()
        self.config = yaml.safe_load(self.raw)

    def test_canonical_contract(self):
        mod.validate_compose(self.raw)
        self.assertNotIn("ports:", self.raw)
        self.assertNotIn("password", self.raw.lower())
        self.assertNotIn("identity-staging", self.raw)
        self.assertNotIn("environment:", self.raw)
        self.assertNotIn("docker.sock", self.raw)
        self.assertNotIn("noTLSVerify", self.raw)

    def test_reject_security_regressions(self):
        def altered(change):
            doc = yaml.safe_load(self.raw)
            change(doc, doc["services"][mod.SERVICE])
            return yaml.safe_dump(doc)
        for label, change in (
            ("public-port", lambda c, s: s.update(ports=["27017:27017"])),
            ("bind-mount", lambda c, s: s["volumes"][0].update(source="identity-data")),
            ("staging-data", lambda c, s: c["volumes"]["identity-production-data"].update(
                name="shadowops-identity-staging-data")),
            ("network-public", lambda c, s: c["networks"]["identity-mongo-egress"].update(internal=False)),
            ("wrong-network", lambda c, s: c["networks"]["identity-mongo-egress"].update(name="default")),
            ("wrong-image", lambda c, s: s.update(image="mongo:latest")),
            ("arm", lambda c, s: s.update(platform="linux/amd64")),
            ("root", lambda c, s: s.update(user="0:0")),
            ("privileged", lambda c, s: s.update(privileged=True)),
            ("restart", lambda c, s: s.update(restart="always")),
            ("read-write", lambda c, s: s.update(read_only=False)),
            ("tls-off", lambda c, s: s["command"].remove("requireTLS")),
            ("no-keyfile", lambda c, s: s["command"].remove("--keyFile")),
            ("staging-replica", lambda c, s: s["command"].__setitem__(1, "identity-staging-rs")),
            ("host-publish", lambda c, s: s.update(network_mode="host")),
            ("socket", lambda c, s: s["volumes"].append({"type": "bind", "source": "/var/run/docker.sock",
                                                   "target": "/var/run/docker.sock"})),
        ):
            with self.subTest(label=label), self.assertRaises(mod.Refused):
                mod.validate_compose(altered(change))

    def test_reject_duplicate_keys_aliases_and_multi_documents(self):
        for raw in (
            self.raw + "\nservices: {}\n",
            "name: evil\nname: allowed\n",
            "name: &a wrong\nservices: *a\n",
            self.raw + "\n---\nname: evil\n",
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(mod.Refused):
                mod.validate_compose(raw)

    def test_private_files_no_symlinks_unsafe_mode_or_wrong_owner(self):
        def info(mode, uid=0, size=50):
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_size=size)
        def metadata(path):
            p = str(path)
            if p.endswith(("mongo.pem", "ca.pem", "replica.key")):
                return info(stat.S_IFREG | 0o400, uid=999)
            return info(stat.S_IFDIR | 0o755)
        with patch.object(Path, "lstat", autospec=True, side_effect=metadata), \
             patch.object(mod.ssl, "create_default_context") as context:
            mod.inspect_private_files()
            context.assert_called_once_with(cafile=str(mod.SECRET_DIR / "ca.pem"))
        for bad, why in (
            (info(stat.S_IFLNK | 0o777, 999), "symlink"),
            (info(stat.S_IFREG | 0o644, 999), "mode"),
            (info(stat.S_IFREG | 0o400, 0), "owner"),
            (info(stat.S_IFREG | 0o400, 999, 0), "empty"),
        ):
            def fail(path):
                return bad if str(path).endswith("replica.key") else metadata(path)
            with self.subTest(why=why), patch.object(Path, "lstat", autospec=True, side_effect=fail), \
                 self.assertRaises(mod.Refused):
                mod.inspect_private_files()

    def test_missing_certificates_fail_closed_and_no_secret_values_logged(self):
        with patch.object(Path, "lstat", side_effect=FileNotFoundError), \
             redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(mod.main(["inspect"]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue().strip(), "IDENTITY_PRODUCTION_MONGO_HOST_REFUSED")

    def test_plan_does_not_connect_or_start(self):
        p = subprocess.run(["python3", str(ROOT / "scripts/identity_production_mongo_host.py"), "plan"],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("backups=not-configured", p.stdout)
        self.assertIn("start=operator-only", p.stdout)

    def test_make_targets_are_read_only(self):
        for action in ("identity-prod-mongo-host-plan", "identity-prod-mongo-host-inspect"):
            p = subprocess.run(["make", "--no-print-directory", "-n", action],
                               cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("scripts/identity_production_mongo_host.py", p.stdout)
            for forbidden in ("docker compose up", "docker volume create", "curl ", "sudo "):
                self.assertNotIn(forbidden, p.stdout)


if __name__ == "__main__":
    unittest.main()
