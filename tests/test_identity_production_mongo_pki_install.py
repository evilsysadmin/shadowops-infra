"""Offline negative tests for the dedicated Mongo production PKI installer."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mongo_pki_host_install", ROOT / "host/identity-production-mongo-pki-install.py",
)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.stage = self.base / "shadowops-mongo-pki-stage"
        self.stage.mkdir(mode=0o700)
        self.stage.chmod(0o700)
        for name in op.NAMES:
            f = self.stage / name
            f.write_bytes(b"fictional-private-test-only-" + name.encode())
            f.chmod(0o600)

    def test_contract_and_exact_names(self):
        self.assertEqual(set(op.NAMES), {"ca.pem", "mongo.pem", "replica.key"})
        self.assertEqual(op.STAGE, Path("/home/ubuntu/shadowops-mongo-pki-stage"))
        self.assertEqual(op.TARGET, Path("/etc/shadowops/identity-production/mongo"))
        p = subprocess.run(
            ["python3", "-I", str(ROOT / "host/identity-production-mongo-pki-install.py"),
             "plan"], capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ca-private=off-host", p.stdout)
        self.assertIn("overwrite=never", p.stdout)

    def test_exact_three_file_stage_and_reject_foreign_files(self):
        valid = op.read_staging(stage=self.stage, operator_uid=os.getuid())
        self.assertEqual(set(valid), set(op.NAMES))
        (self.stage / "ca-private.key").write_text("forbidden")
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid())
        (self.stage / "ca-private.key").unlink()
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid() + 1)

    def test_symlink_hardlink_mode_and_nonregular_file_denied(self):
        name = self.stage / "mongo.pem"
        original = name.read_bytes()
        name.unlink()
        name.symlink_to(self.base / "other")
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid())
        name.unlink()
        name.write_bytes(original)
        name.chmod(0o644)
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid())
        name.chmod(0o600)
        linked = self.base / "linked"
        os.link(name, linked)
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid())
        linked.unlink()
        name.unlink()
        name.mkdir()
        with self.assertRaises(op.Refused):
            op.read_staging(stage=self.stage, operator_uid=os.getuid())

    def test_reject_oversized_and_empty_secret(self):
        f = self.stage / "replica.key"
        for data in (b"", b"x"*2049):
            f.write_bytes(data)
            with self.assertRaises(op.Refused):
                op.read_staging(stage=self.stage, operator_uid=os.getuid())

    def test_new_private_install_files_no_overwrite(self):
        target = self.base / "production" / "mongo"
        target.parent.mkdir(mode=0o700)
        payload = op.read_staging(stage=self.stage, operator_uid=os.getuid())
        op.write_new_files(target, payload,
                           file_uid=os.getuid(), file_gid=os.getgid())
        self.assertEqual(set(p.name for p in target.iterdir()), set(op.NAMES))
        for name, data in payload.items():
            f = target / name
            self.assertEqual(f.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o400)
        with self.assertRaises(op.Refused):
            op.write_new_files(target, payload,
                               file_uid=os.getuid(), file_gid=os.getgid())
        self.assertEqual(set(p.name for p in target.iterdir()), set(op.NAMES))
        with self.assertRaises(op.Refused):
            op.write_new_files(self.base / "other-dest",
                               {"ca-private.key": b"x"})

    def test_no_adoption_of_existing_or_symlink_destination(self):
        target = self.base / "source"
        target.mkdir()
        with self.assertRaises(op.Refused):
            op.absent(target)
        target.rmdir()
        target.symlink_to(self.stage)
        with self.assertRaises(op.Refused):
            op.absent(target)

    def test_operator_denied_ci_rootless_wrong_host_no_tty_and_ack(self):
        tty = SimpleNamespace(isatty=lambda: True)
        no_tty = SimpleNamespace(isatty=lambda: False)
        base = dict(env={}, euid=0, stdin=tty, stdout=tty,
                    hostname="chessbackend", machine="aarch64",
                    mutation=True, prompt=lambda _: op.ACK)
        cases = (
            {"env": {"CI": "true"}},
            {"env": {"GITHUB_ACTIONS": "true"}},
            {"euid": 1001},
            {"hostname": "foreign"},
            {"machine": "x86_64"},
            {"stdin": no_tty},
            {"stdout": no_tty},
            {"prompt": lambda _: "DENY"},
        )
        for case in cases:
            with self.subTest(case=list(case)), self.assertRaises(op.Refused):
                op.require_operator(**(base | case))

    def test_preflight_performs_readonly_staging_crypto_and_docker_inventory(self):
        payload = {name: b"test" for name in op.NAMES}
        with mock.patch.object(op, "require_operator") as auth, \
             mock.patch.object(op.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch.object(op.host, "validate_compose") as contract, \
             mock.patch.object(op, "validate_namespace") as ns, \
             mock.patch.object(op, "read_staging", return_value=payload) as source, \
             mock.patch.object(op.material, "verify_crypto") as crypto, \
             mock.patch.object(op.start, "ensure_empty") as empty:
            self.assertEqual(op.preflight(), payload)
            auth.assert_called_once_with(mutation=False)
            contract.assert_called_once()
            ns.assert_called_once()
            self.assertEqual(source.call_count, 2)
            crypto.assert_called_once()
            empty.assert_called_once()

    def test_fail_before_docker_on_changed_staging_or_invalid_tls(self):
        payload = {name: b"test" for name in op.NAMES}
        with mock.patch.object(op, "require_operator"), \
             mock.patch.object(op.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch.object(op.host, "validate_compose"), \
             mock.patch.object(op, "validate_namespace"), \
             mock.patch.object(op.material, "verify_crypto"), \
             mock.patch.object(op, "read_staging",
                               side_effect=[payload, dict(payload, **{"mongo.pem": b"other"})]), \
             mock.patch.object(op.start, "ensure_empty") as docker, \
             self.assertRaises(op.Refused):
            op.preflight()
        docker.assert_not_called()
        with mock.patch.object(op, "require_operator"), \
             mock.patch.object(op.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch.object(op.host, "validate_compose"), \
             mock.patch.object(op, "validate_namespace"), \
             mock.patch.object(op, "read_staging", return_value=payload), \
             mock.patch.object(op.material, "verify_crypto", side_effect=ValueError("bad TLS")), \
             mock.patch.object(op.start, "ensure_empty") as docker, \
             self.assertRaises(ValueError):
            op.preflight()
        docker.assert_not_called()

    def test_ci_does_not_install_or_touch_host(self):
        for action in ("inspect", "install"):
            p = subprocess.run(
                ["python3", "-I", str(ROOT / "host/identity-production-mongo-pki-install.py"),
                 action], capture_output=True, text=True, timeout=10,
                env={"CI": "true", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
            self.assertEqual(p.returncode, 1)
            self.assertIn("IDENTITY_PRODUCTION_MONGO_PKI_INSTALL_REFUSED", p.stderr)
            self.assertNotIn("Traceback", p.stderr)

    def test_make_target_separation(self):
        for action in ("plan", "inspect", "install"):
            target = "identity-prod-mongo-pki-" + action
            p = subprocess.run(["make", "-n", "--no-print-directory", target],
                               cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("identity-production-mongo-pki-install.py " + action, p.stdout)
            self.assertNotIn("sudo ", p.stdout)
            self.assertNotIn("docker compose up", p.stdout)


if __name__ == "__main__":
    unittest.main()
