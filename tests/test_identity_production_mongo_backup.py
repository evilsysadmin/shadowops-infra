"""Synthetic-only tests: no OCI, Mongo, credentials, cloud, or Docker sockets."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "identity_prod_backup", ROOT / "scripts/identity_production_mongo_backup.py"
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupContractTests(unittest.TestCase):
    def test_plan_is_credentialless_and_read_only(self):
        p = subprocess.run(["python3", str(ROOT / "scripts/identity_production_mongo_backup.py"),
                            "plan"], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("encryption=age-before-disk", p.stdout)
        self.assertIn("overwrite=deny", p.stdout)
        self.assertIn("restore=drill-required", p.stdout)

    def test_backup_denied_without_explicit_operator_enable(self):
        with patch.object(backup, "inspect_local") as inspect:
            with self.assertRaises(backup.Refused):
                backup.backup({})
        inspect.assert_not_called()

    def test_ci_and_invalid_destination_are_refused(self):
        env = {
            "IDENTITY_PRODUCTION_BACKUP_BUCKET": "private-prod-backups",
            "IDENTITY_PRODUCTION_BACKUP_NAMESPACE": "private_namespace",
        }
        for extra in ({"CI": "1"}, {"GITHUB_ACTIONS": "true"},
                      {"IDENTITY_PRODUCTION_BACKUP_BUCKET": "bad;echo"},
                      {"IDENTITY_PRODUCTION_BACKUP_NAMESPACE": "../"},
                      {}):
            with self.subTest(extra=extra), \
                 patch.object(backup.host, "validate_compose") as compose, \
                 self.assertRaises(backup.Refused):
                backup.inspect_local({**env, **extra}, euid=1, resolve=lambda x: "/bin/" + x)
                compose.assert_not_called()

    def test_native_tools_and_root_mandatory(self):
        env = {"IDENTITY_PRODUCTION_BACKUP_BUCKET": "prod-backups",
               "IDENTITY_PRODUCTION_BACKUP_NAMESPACE": "tenant01"}
        with self.assertRaises(backup.Refused):
            backup.inspect_local(env, euid=0, resolve=lambda _: None)

    def test_passwords_never_in_arguments(self):
        args = backup.dump_args("a" * 64)
        self.assertIn("--config", args)
        self.assertIn("/run/mongo/backup-tools.yml", args)
        self.assertIn("--archive", args)
        self.assertIn("--oplog", args)
        self.assertIn("--gzip", args)
        self.assertNotIn("--password", args)
        self.assertNotIn("--uri", args)
        self.assertNotIn("staging", " ".join(args))
        name = "shadowops/identity/production/mongo/2026/11/20/example.archive.gz.age"
        put = backup.put_args("tenant01", "safe-prod-backups", name, Path("/tmp/safe.age"))
        self.assertEqual(put[:3], ["oci", "--auth", "instance_principal"])
        self.assertIn("--no-overwrite", put)
        self.assertIn("--verify-checksum", put)
        self.assertNotIn("--force", put)
        self.assertNotIn("delete", put)
        self.assertIn("--name", backup.head_args("tenant01", "safe-prod-backups", name))

    def test_runtime_proof_rejects_staging_and_unhealthy_mongo(self):
        cid = "a" * 64
        runtime = {
            "Config": {"Labels": {
                "com.docker.compose.project": backup.host.PROJECT,
                "com.docker.compose.service": backup.host.SERVICE},
                "Image": backup.host.IMAGE, "User": "999:999"},
            "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "PortBindings": {}},
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Networks": {backup.host.NETWORK: {}}},
            "Mounts": [
                {"Destination": "/data/db", "Type": "volume", "Name": backup.host.VOLUME},
                {"Destination": "/run/mongo", "Source": str(backup.host.SECRET_DIR), "RW": False},
            ],
        }
        with patch.object(backup, "run_json_no_format", return_value=[cid]), \
             patch.object(backup, "run_json", return_value=runtime):
            self.assertEqual(backup.live_mongo_container(), cid)
            runtime["Config"]["Labels"]["com.docker.compose.project"] = "shadowops-identity-staging"
            with self.assertRaises(backup.Refused):
                backup.live_mongo_container()
            runtime["Config"]["Labels"]["com.docker.compose.project"] = backup.host.PROJECT
            runtime["State"]["Health"]["Status"] = "unhealthy"
            with self.assertRaises(backup.Refused):
                backup.live_mongo_container()
            runtime["State"]["Health"]["Status"] = "healthy"
            runtime["NetworkSettings"]["Networks"]["shadowops-identity-staging-database"] = {}
            with self.assertRaises(backup.Refused):
                backup.live_mongo_container()

    def test_remote_receipt_requires_etag_and_matching_ciphertext_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "only-cipher.age"
            src.write_bytes(b"encrypted-not-real")
            with patch.object(backup, "run_json",
                              side_effect=[{"etag": "uploaded"}, {
                                  "etag": "uploaded", "content-length": str(src.stat().st_size)}]) as run:
                backup.upload_verified("tenant01", "prod-backups", "fixed-object", src)
                self.assertEqual(run.call_count, 2)
            for status in ({"output": "The object already exists and was not overwritten"},
                           {"etag": ""}):
                with self.subTest(status=status), \
                     patch.object(backup, "run_json", return_value=status), \
                     self.assertRaises(backup.Refused):
                    backup.upload_verified("tenant01", "prod-backups", "fixed-object", src)
            with patch.object(backup, "run_json", side_effect=[
                    {"etag": "yes"}, {"etag": "yes", "content-length": 0}]), \
                 self.assertRaises(backup.Refused):
                backup.upload_verified("tenant01", "prod-backups", "fixed-object", src)

    def test_success_unlinks_ciphertext_only_after_verified_upload(self):
        @contextmanager
        def fake_lock():
            yield
        env = {"IDENTITY_PRODUCTION_BACKUP_ENABLE": backup.ENABLE}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(backup, "BACKUP_DIR", Path(tmp)), \
             patch.object(backup, "single_writer", fake_lock), \
             patch.object(backup, "inspect_local", return_value=("ns", "bucket")), \
             patch.object(backup, "live_mongo_container", return_value="a" * 64), \
             patch.object(backup, "encrypted_dump",
                          side_effect=lambda _, p: p.write_bytes(b"ciphertext" * 100)), \
             patch.object(backup, "upload_verified") as upload:
            key = backup.backup(env)
            self.assertIn(".archive.gz.age", key)
            self.assertEqual(list(Path(tmp).iterdir()), [])
            self.assertEqual(upload.call_count, 1)

    def test_upload_failure_keeps_only_encrypted_artifact(self):
        @contextmanager
        def fake_lock():
            yield
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(backup, "BACKUP_DIR", Path(tmp)), \
             patch.object(backup, "single_writer", fake_lock), \
             patch.object(backup, "inspect_local", return_value=("ns", "bucket")), \
             patch.object(backup, "live_mongo_container", return_value="a" * 64), \
             patch.object(backup, "encrypted_dump",
                          side_effect=lambda _, p: p.write_bytes(b"ciphertext" * 100)), \
             patch.object(backup, "upload_verified", side_effect=backup.Refused("upload")):
            with self.assertRaises(backup.Refused):
                backup.backup({"IDENTITY_PRODUCTION_BACKUP_ENABLE": backup.ENABLE})
            files = list(Path(tmp).iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"ciphertext" * 100)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_disabled_timer_and_hardened_units(self):
        unit = (ROOT / "host/identity-production-mongo-backup.service").read_text()
        timer = (ROOT / "host/identity-production-mongo-backup.timer").read_text()
        for requirement in (
            "Type=oneshot", "User=root", "NoNewPrivileges=true",
            "ProtectSystem=strict", "EnvironmentFile=/etc/shadowops/identity-production/backup.env",
            "identity_production_mongo_backup.py backup",
        ):
            self.assertIn(requirement, unit)
        self.assertIn("Persistent=true", timer)
        self.assertIn("OnCalendar=", timer)
        self.assertNotIn("WantedBy=", unit)
        self.assertIn("WantedBy=timers.target", timer)

    def test_make_backup_targets_safe(self):
        for target, action in (("identity-prod-mongo-backup-plan", "plan"),
                               ("identity-prod-mongo-backup-inspect", "inspect")):
            p = subprocess.run(["make", "--no-print-directory", "-n", target], cwd=ROOT,
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("identity_production_mongo_backup.py " + action, p.stdout)
            self.assertNotIn("sudo ", p.stdout)


if __name__ == "__main__":
    unittest.main()
