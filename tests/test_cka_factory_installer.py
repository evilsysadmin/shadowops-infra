"""Offline safety and behavioral tests for the manual CKA staging installer."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "host/install-cka-factory-staging.py"
spec = importlib.util.spec_from_file_location("cka_factory_installer", SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
INFRA_SHA = "a" * 40
CKA_SHA = "b" * 40
DUMMY_UNIT = (ROOT / "host/cka-factory-staging.service").read_bytes()
ACCOUNT = SimpleNamespace(pw_uid=2001, pw_gid=2001, pw_shell="/usr/sbin/nologin",
                          pw_dir="/nonexistent")


class TestCKAFactoryInstaller(unittest.TestCase):
    def test_explicit_sha_and_clean_root_owned_checkouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            (source / ".git").mkdir(parents=True)
            app = root / "app"
            venv_bin = app / "venv/bin"
            venv_bin.mkdir(parents=True)
            (venv_bin / "python").write_text("fake executable")
            (venv_bin / "python").chmod(0o755)
            origin = root / "unit"
            origin.write_bytes(DUMMY_UNIT)
            with patch.object(installer, "INFRA", source), \
                 patch.object(installer, "SOURCE", source), \
                 patch.object(installer, "APP", app), \
                 patch.object(installer, "PYTHON", venv_bin / "python"), \
                 patch.object(installer, "UNIT_SOURCE", origin), \
                 patch.object(installer, "UNIT_DEST", root / "unit-destination"), \
                 patch.object(installer, "WORKSPACE", root / "workspace"), \
                 patch.object(installer, "trusted") as trust:
                calls = []
                def fake_run(args):
                    calls.append(args)
                    if args[-2:] == ["rev-parse", "HEAD"]:
                        return INFRA_SHA if len(calls) <= 1 else CKA_SHA
                    if args[-1] == "--untracked-files=no":
                        return ""
                    if args[0] == str(venv_bin / "python"):
                        return str(source)
                    return ""
                with patch.object(installer, "command", side_effect=fake_run):
                    self.assertEqual(installer.verify_runtime(INFRA_SHA, CKA_SHA),
                                     DUMMY_UNIT)
                self.assertTrue(trust.called)
                self.assertEqual(len(calls), 5)

    def test_invalid_sha_fails_before_filesystem_or_process_calls(self):
        with patch.object(installer, "verify_checkout") as checkout:
            for infra, app in (("not-a-sha", CKA_SHA), (INFRA_SHA, "ABC" * 13),
                               (INFRA_SHA, "../etc")):
                with self.subTest(infra=infra, app=app):
                    with self.assertRaises(installer.InstallError):
                        installer.verify_runtime(infra, app)
            checkout.assert_not_called()

    def test_checkout_mismatch_and_dirty_state_both_fail_closed(self):
        with patch.object(installer, "trusted"):
            with patch.object(installer, "command", return_value="c" * 40):
                with self.assertRaisesRegex(installer.InstallError, "SHA mismatch"):
                    installer.verify_checkout(Path("/nonexistent"), INFRA_SHA)
            with patch.object(installer, "command", side_effect=[INFRA_SHA, " M backend/cka_sim"]):
                with self.assertRaisesRegex(installer.InstallError, "tracked modifications"):
                    installer.verify_checkout(Path("/nonexistent"), INFRA_SHA)

    def test_rejects_unauthorized_unit_content_and_existing_foreign_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, target = root / "candidate", root / "target"
            src.write_bytes(DUMMY_UNIT.replace(
                b"factory-run --workspace", b"factory-run --execute --workspace"))
            with patch.object(installer, "verify_checkout"), \
                 patch.object(installer, "trusted"), \
                 patch.object(installer, "APP", root), \
                 patch.object(installer, "SOURCE", root), \
                 patch.object(installer, "PYTHON", root / "python"), \
                 patch.object(installer, "UNIT_SOURCE", src), \
                 patch.object(installer, "UNIT_DEST", target), \
                 patch.object(installer, "WORKSPACE", root / "workspace"), \
                 patch.object(installer.os, "access", return_value=True), \
                 patch.object(installer, "command", return_value=str(root)):
                with self.assertRaisesRegex(installer.InstallError, "policy changed"):
                    installer.verify_runtime(INFRA_SHA, CKA_SHA)
                src.write_bytes(DUMMY_UNIT)
                target.write_text("foreign unit")
                with self.assertRaisesRegex(installer.InstallError, "no overwrites"):
                    installer.verify_runtime(INFRA_SHA, CKA_SHA)

    def test_rejects_workspace_symlink_wrong_mode_or_wrong_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "workspace"
            with patch.object(installer, "WORKSPACE", root):
                outside = parent / "outside"
                outside.mkdir()
                root.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(installer.InstallError, "symlink"):
                    installer.verify_workspace(ACCOUNT)
                root.unlink()
                root.mkdir(mode=0o755)
                with self.assertRaisesRegex(installer.InstallError, "unsafe"):
                    installer.verify_workspace(ACCOUNT)
                root.chmod(0o700)
                with self.assertRaisesRegex(installer.InstallError, "unsafe"):
                    installer.verify_workspace(ACCOUNT)

    def test_manual_install_needs_root_and_exact_confirmation(self):
        with patch.object(installer.os, "geteuid", return_value=1000), \
             patch.object(installer, "preflight") as preflight:
            with self.assertRaisesRegex(installer.InstallError, "Root"):
                installer.install(INFRA_SHA, CKA_SHA, installer.ACK)
            preflight.assert_not_called()
        with patch.object(installer.os, "geteuid", return_value=0), \
             patch.object(installer, "preflight") as preflight:
            with self.assertRaisesRegex(installer.InstallError, "confirmation"):
                installer.install(INFRA_SHA, CKA_SHA, "")
            preflight.assert_not_called()

    def test_explicit_install_creates_only_isolated_workspace_and_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "data" / "cka-factory-staging"
            workspace.parent.mkdir()
            unit = root / "systemd" / "shadowops-cka-factory-staging.service"
            unit.parent.mkdir()
            with patch.object(installer.os, "geteuid", return_value=0), \
                 patch.object(installer, "preflight", return_value=DUMMY_UNIT) as preflight, \
                 patch.object(installer, "installed_account", return_value=ACCOUNT), \
                 patch.object(installer, "WORKSPACE", workspace), \
                 patch.object(installer, "UNIT_DEST", unit), \
                 patch.object(installer, "verify_workspace"), \
                 patch.object(installer.os, "chown") as chown:
                installer.install(INFRA_SHA, CKA_SHA, installer.ACK)
                self.assertEqual(unit.read_bytes(), DUMMY_UNIT)
                self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
                chown.assert_called_once_with(workspace, 2001, 2001)
                preflight.assert_called_once_with(INFRA_SHA, CKA_SHA)
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["data", "systemd"])

    def test_installer_is_never_called_by_any_actions_workflow(self):
        script = SCRIPT.read_text()
        self.assertNotIn("systemctl start", script)
        self.assertNotIn("systemctl enable", script)
        self.assertNotIn("apt install", script)
        self.assertNotIn("pip install", script)
        self.assertNotIn("curl ", script)
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            self.assertNotIn("install-cka-factory-staging.py",
                             workflow.read_text(), workflow.name)


if __name__ == "__main__":
    unittest.main()
