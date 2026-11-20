"""Synthetic tests for dedicated Mongo backup user (no actual Mongo or OCI)."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "prod_backup_user", ROOT / "host/identity-production-mongo-backup-user.py")
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
CID = "a" * 64


class BackupUserTests(unittest.TestCase):
    def test_static_role_and_no_secret_arguments(self):
        a = op.argv_for(CID)
        self.assertEqual(a[:4], ["docker", "exec", "-it", CID])
        self.assertIn("--tls", a)
        self.assertIn("--tlsCAFile", a)
        self.assertEqual(a[-2:], ["--eval", op.JS])
        self.assertIn("--username", a)
        self.assertIn(op.admin_op.USER, a)
        self.assertIn("--authenticationDatabase", a)
        self.assertNotIn("--password", a)
        self.assertNotIn("identity_prod_admin", op.JS)
        self.assertNotIn("staging", " ".join(a).lower())
        self.assertIn('roles:[{role:"backup",db:"admin"}]', op.JS)
        self.assertIn('if(existing){quit(40);}', op.JS)
        self.assertIn('pwd!==repeated', op.JS)
        self.assertIn('pwd.length<32', op.JS)
        self.assertEqual(op.JS.count("passwordPrompt()"), 2)
        self.assertIn('user.roles[0].role!=="backup"', op.JS)
        self.assertNotIn('role:"root"', op.JS)
        self.assertNotIn("drop", op.JS)
        self.assertNotIn("delete", op.JS)
        for bad in ("bad", "a"*65, "g"*64):
            with self.assertRaises(op.Refused):
                op.argv_for(bad)

    def test_root_tty_ack_ci_denies_before_docker(self):
        cases = ("not_root", "no_tty_in", "no_tty_out", "ci", "bad_ack")
        for kind in cases:
            with self.subTest(kind=kind), self.assertRaises(op.Refused), \
                 mock.patch.object(op.replica, "verified_container") as conn:
                op.create(confirm=lambda: op.authorize(
                    euid=1 if kind=="not_root" else 0,
                    stdin=SimpleNamespace(isatty=lambda: kind != "no_tty_in"),
                    stdout=SimpleNamespace(isatty=lambda: kind != "no_tty_out"),
                    env={"CI": "1"} if kind=="ci" else {},
                    prompt=lambda _: "WRONG" if kind=="bad_ack" else op.ACK,
                ))
                conn.assert_not_called()

    def test_primary_gate_no_user_creation(self):
        with mock.patch.object(op.replica.operator, "single_operator", return_value=nullcontext()), \
             mock.patch.object(op.replica, "verified_container", return_value=CID), \
             mock.patch.object(op.replica, "run_mongosh", return_value="NONPRIMARY"), \
             mock.patch.object(op, "argv_for") as argv, self.assertRaises(op.Refused):
            op.create(confirm=lambda: None)
            argv.assert_not_called()

    def test_one_interactive_command_only_no_capture(self):
        runner = mock.Mock(return_value=SimpleNamespace(returncode=0))
        with mock.patch.object(op.replica.operator, "single_operator", return_value=nullcontext()), \
             mock.patch.object(op.replica, "verified_container", return_value=CID), \
             mock.patch.object(op.replica, "run_mongosh", return_value="PRIMARY"):
            op.create(confirm=lambda: None, runner=runner)
        runner.assert_called_once()
        args, kw = runner.call_args
        self.assertEqual(args[0], op.argv_for(CID))
        self.assertEqual(kw, {"check": False, "timeout": 180})
        for banned in ("input", "env", "shell", "stdout", "stderr", "capture_output"):
            self.assertNotIn(banned, kw)

    def test_failed_user_creation_no_retry(self):
        for result in (
            SimpleNamespace(returncode=1),
            subprocess.TimeoutExpired(["docker"], 180),
            OSError("DO-NOT-LOG-PRIVATE-DATA"),
        ):
            with self.subTest(result=str(type(result))), \
                 mock.patch.object(op.replica.operator, "single_operator", return_value=nullcontext()), \
                 mock.patch.object(op.replica, "verified_container", return_value=CID), \
                 mock.patch.object(op.replica, "run_mongosh", return_value="PRIMARY"):
                runner = mock.Mock(
                    side_effect=result if isinstance(result, Exception) else None,
                    return_value=result if not isinstance(result, Exception) else None,
                )
                with self.assertRaises(op.Refused):
                    op.create(confirm=lambda: None, runner=runner)
                runner.assert_called_once()

    def test_inspect_does_not_falsely_report_user(self):
        with mock.patch.object(op.replica, "inspect", return_value="PRIMARY"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(op.main(["inspect"]), 0)
            self.assertIn("account_state=not-verified", out.getvalue())

    def test_ci_create_is_rejected_no_traceback(self):
        p = subprocess.run(
            ["python3", "-I", str(ROOT / "host/identity-production-mongo-backup-user.py"),
             "create"], capture_output=True, text=True, timeout=10,
            env={"CI": "true", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        self.assertEqual(p.returncode, 1)
        self.assertIn("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_REFUSED", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_make_targets_and_no_implicit_execution(self):
        for target, action in (
            ("identity-prod-mongo-backup-user-plan", "plan"),
            ("identity-prod-mongo-backup-user-inspect", "inspect"),
            ("identity-prod-mongo-backup-user-create", "create"),
        ):
            with self.subTest(target=target):
                p = subprocess.run(["make", "--no-print-directory", "-n", target],
                                   cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("host/identity-production-mongo-backup-user.py " + action, p.stdout)
                self.assertNotIn("sudo ", p.stdout)
                self.assertNotIn("ssh ", p.stdout)


if __name__ == "__main__":
    unittest.main()
