"""Atlas 0600 deploy.lock hardening, authorized legacy repair, zero Docker/Atlas.

Run under normal CI user; temporary fixture ownership is injected, not used
by the installed root operator. No real host file is ever touched.
"""
import contextlib
from importlib.util import module_from_spec, spec_from_file_location
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_atlas_lock as locks

p = ROOT / "host/identity-atlas-staging-lock.py"
spec = spec_from_file_location("atlas_lock_host_operator", p)
host = module_from_spec(spec)
spec.loader.exec_module(host)


class PrivateLockTests(unittest.TestCase):
    def run_private(self, operation):
        with tempfile.TemporaryDirectory() as temp, patch.object(locks, "_directory"):
            return operation(Path(temp), os.getuid(), os.getgid())

    def test_new_lock_is_mode_0600_even_with_umask_022(self):
        def body(state, uid, gid):
            prior = os.umask(0o022)
            try:
                with locks.exclusive(state, uid=uid, gid=gid):
                    info = (state / "deploy.lock").lstat()
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                    self.assertEqual(info.st_size, 0)
                    self.assertEqual(info.st_nlink, 1)
                    self.assertEqual(locks.status(state, uid=uid, gid=gid), "secure")
            finally:
                os.umask(prior)
        self.run_private(body)

    def test_legacy_0644_is_rejected_until_explicit_guarded_repair(self):
        def body(state, uid, gid):
            lock = state / "deploy.lock"
            lock.touch(mode=0o644)
            lock.chmod(0o644)
            old_inode = lock.stat().st_ino
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "legacy-0644")
            with self.assertRaises(locks.AtlasLockBlocked):
                with locks.exclusive(state, uid=uid, gid=gid):
                    self.fail("must not acquire legacy lock")
            with patch.object(locks.os, "geteuid", return_value=0):
                self.assertEqual(locks.repair_legacy(state, uid=uid, gid=gid), "repaired-legacy-0644")
                self.assertEqual(locks.repair_legacy(state, uid=uid, gid=gid), "already-secure")
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "secure")
            self.assertEqual(lock.stat().st_ino, old_inode)
            with locks.exclusive(state, uid=uid, gid=gid):
                pass
        self.run_private(body)

    def test_unsafe_types_nonempty_hardlink_and_wrong_group_fail_closed(self):
        def body(state, uid, gid):
            lock = state / "deploy.lock"
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "missing")
            with patch.object(locks.os, "geteuid", return_value=0):
                with self.assertRaises(OSError):
                    locks.repair_legacy(state, uid=uid, gid=gid)
            lock.write_bytes(b"PRIVATE_STUFF")
            lock.chmod(0o644)
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "unsafe")
            with patch.object(locks.os, "geteuid", return_value=0):
                with self.assertRaises(locks.AtlasLockBlocked):
                    locks.repair_legacy(state, uid=uid, gid=gid)
            lock.write_bytes(b"")
            extra = state / "extra"
            os.link(lock, extra)
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "unsafe")
            extra.unlink()
            lock.unlink()
            lock.symlink_to(state / "missing")
            self.assertEqual(locks.status(state, uid=uid, gid=gid), "unsafe")
            with patch.object(locks.os, "geteuid", return_value=0):
                with self.assertRaises(OSError):
                    locks.repair_legacy(state, uid=uid, gid=gid)
            lock.unlink()
            lock.touch()
            lock.chmod(0o644)
            self.assertEqual(locks.status(state, uid=uid, gid=gid + 1), "unsafe")
        self.run_private(body)

    def test_pending_journal_refuses_repair_even_for_legacy(self):
        def body(state, uid, gid):
            lock = state / "deploy.lock"
            lock.touch()
            lock.chmod(0o644)
            (state / "atlas-deploy-pending.json").write_text("not read")
            with patch.object(locks.os, "geteuid", return_value=0):
                with self.assertRaises(locks.AtlasLockBlocked):
                    locks.repair_legacy(state, uid=uid, gid=gid)
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)
        self.run_private(body)

    def test_busy_lock_fails_repair_without_changing_permissions(self):
        def body(state, uid, gid):
            lock = state / "deploy.lock"
            lock.touch()
            lock.chmod(0o644)
            import fcntl
            with lock.open("rb+") as f:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    with patch.object(locks.os, "geteuid", return_value=0):
                        with self.assertRaises(BlockingIOError):
                            locks.repair_legacy(state, uid=uid, gid=gid)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)
        self.run_private(body)

    def test_non_root_repair_is_denied(self):
        with patch.object(locks.os, "geteuid", return_value=1001):
            with self.assertRaises(locks.AtlasLockBlocked):
                locks.repair_legacy()

    def test_root_operator_exposes_only_fixed_status_and_repair_receipts(self):
        for operation, expected in (
            ("status", "IDENTITY_ATLAS_LOCK_STATUS state=legacy-0644"),
            ("repair", "IDENTITY_ATLAS_LOCK_REPAIR result=repaired-legacy-0644"),
        ):
            output = io.StringIO()
            with patch.object(host.os, "geteuid", return_value=0), patch.object(
                host.sys, "argv", ["operator", operation]
            ), patch.object(host, "status", return_value="legacy-0644"), patch.object(
                host, "repair_legacy", return_value="repaired-legacy-0644"
            ), contextlib.redirect_stdout(output):
                self.assertEqual(host.main(), 0)
            self.assertEqual(output.getvalue().strip(), expected)
        output = io.StringIO()
        with patch.object(host.os, "geteuid", return_value=0), patch.object(
            host.sys, "argv", ["operator", "repair"]
        ), patch.object(host, "repair_legacy", side_effect=ValueError("PRIVATE_SECRET")), contextlib.redirect_stdout(output):
            self.assertEqual(host.main(), 1)
        self.assertEqual(output.getvalue().strip(),
                         "IDENTITY_ATLAS_LOCK_BLOCKED reason=unsafe-or-busy")

    def test_installed_operators_are_unified_and_deploy_does_not_auto_repair(self):
        paths = [
            "host/identity-atlas-staging-preflight.py",
            "host/identity-atlas-staging-canary.py",
            "host/identity-atlas-staging-backup.py",
        ]
        for path in paths:
            text = (ROOT / path).read_text()
            self.assertIn("from identity_staging_atlas_lock import exclusive as atlas_lock", text)
            self.assertIn("with atlas_lock(STATE):", text)
            self.assertNotIn("'deploy.lock').open('a')", text)
            self.assertNotIn("repair_legacy(", text)
        deploy = (ROOT / "host/identity-atlas-staging-deploy.py").read_text()
        self.assertIn("os.O_NOFOLLOW, 0o600", deploy)
        self.assertIn("meta.st_mode & 0o077", deploy)
        self.assertNotIn("repair_legacy(", deploy)
        install = (ROOT / "host/install-identity-staging.sh").read_text()
        for item in ("scripts/identity_staging_atlas_lock.py",
                     "host/identity-atlas-staging-lock.py",
                     "/usr/local/lib/shadowops/identity_staging_atlas_lock.py",
                     "/usr/local/sbin/shadowops-identity-atlas-lock"):
            self.assertIn(item, install)
        sudoers = (ROOT / "host/identity-staging.sudoers").read_text()
        self.assertIn("/usr/local/sbin/shadowops-identity-atlas-lock status", sudoers)
        self.assertIn("/usr/local/sbin/shadowops-identity-atlas-lock repair", sudoers)
        self.assertNotIn("identity-atlas-lock *", sudoers)

    def test_ssh_script_is_fixed_and_has_separate_explicit_repair(self):
        path = ROOT / "host/check-identity-atlas-lock-over-ssh.sh"
        subprocess.run(["bash", "-n", str(path)], timeout=10, check=True)
        source = path.read_text()
        for expected in ("stale-main", "dirty-checkout", "reason=unsafe-host-state",
                         "state=legacy-0644", "IDENTITY_ATLAS_LOCK_SSH_REPAIRED",
                         "inspect-identity-atlas-release-failure-over-ssh.sh",
                         "sudo --non-interactive $operator repair"):
            self.assertIn(expected, source)
        self.assertNotIn("atlas-deploy deploy", source)
        self.assertNotIn("sudo docker", source)
        self.assertNotIn("rm -f", source)
        self.assertNotIn("chmod 777", source)


if __name__ == "__main__":
    unittest.main()
