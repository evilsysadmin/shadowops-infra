"""Offline negative tests for the privileged FIRST MongoDB user bootstrap."""
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_admin", ROOT / "host/identity-production-mongo-admin.py"
)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
CID = "a" * 64


class FirstAdminTests(unittest.TestCase):
    def test_plan_no_secret_no_docker_and_isolated_python(self):
        for mode in ([], ["-I"]):
            with self.subTest(mode=mode):
                p = subprocess.run(
                    ["python3", *mode, str(ROOT / "host/identity-production-mongo-admin.py"),
                     "plan"], capture_output=True, text=True, timeout=10, cwd="/tmp",
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CI": "true"},
                )
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("FIRST_ADMIN_PLAN", p.stdout)
                self.assertIn("password=mongosh-tty-prompt", p.stdout)
                self.assertNotIn("Traceback", p.stderr)

    def test_only_fixed_argv_and_password_inside_mongosh(self):
        cmd = op.first_admin_argv(CID)
        self.assertEqual(cmd[:4], ["docker", "exec", "-it", CID])
        self.assertIn("--tls", cmd)
        self.assertIn("--tlsCAFile", cmd)
        self.assertIn("--norc", cmd)
        self.assertEqual(cmd[-2:], ["--eval", op.CREATE_JS])
        self.assertEqual(cmd[-3], op.replica.DESTINATION)
        self.assertEqual(op.CREATE_JS.count("passwordPrompt()"), 2)
        self.assertIn('createUser:"identity_prod_admin"', op.CREATE_JS)
        self.assertIn('roles:[{role:"root",db:"admin"}]', op.CREATE_JS)
        self.assertIn('mechanisms:["SCRAM-SHA-256"]', op.CREATE_JS)
        self.assertIn('pwd.length<32', op.CREATE_JS)
        self.assertIn('pwd!==again', op.CREATE_JS)
        self.assertIn('admin.auth("identity_prod_admin",pwd)', op.CREATE_JS)
        self.assertIn('created.roles[0].role!=="root"', op.CREATE_JS)
        self.assertNotIn("dropDatabase", op.CREATE_JS)
        self.assertNotIn("staging", " ".join(cmd))
        self.assertNotIn("--password", cmd)
        self.assertNotIn("--username", cmd)
        self.assertNotIn("--eval", cmd[:-2])
        for invalid in ("staging-identity", "a"*11, "g"*64, "a"*65, ""):
            with self.subTest(invalid=invalid), self.assertRaises(op.Refused):
                op.first_admin_argv(invalid)

    def test_root_tty_and_ack_before_any_mongo_activity(self):
        for case in ("not_root", "non_tty_in", "non_tty_out", "ci", "wrong_ack"):
            stdin = SimpleNamespace(isatty=lambda: case != "non_tty_in")
            stdout = SimpleNamespace(isatty=lambda: case != "non_tty_out")
            env = {"CI": "true"} if case == "ci" else {}
            with self.subTest(case=case), self.assertRaises(op.Refused), \
                 mock.patch.object(op.replica, "verified_container") as verified:
                op.create_first_admin(
                    confirm=lambda: op.confirm_operator(
                        euid=1001 if case == "not_root" else 0,
                        stdin=stdin, stdout=stdout, env=env,
                        prompt=lambda _: "wrong" if case == "wrong_ack" else op.ACK,
                    )
                )
                verified.assert_not_called()

    def test_primary_required_before_password_prompt(self):
        with mock.patch.object(op.replica.operator, "single_operator", return_value=nullcontext()), \
             mock.patch.object(op.replica, "verified_container", return_value=CID), \
             mock.patch.object(op.replica, "run_mongosh", return_value="NONPRIMARY"), \
             mock.patch.object(op, "first_admin_argv") as argv, \
             self.assertRaises(op.Refused):
            op.create_first_admin(confirm=lambda: None)
            argv.assert_not_called()

    def test_success_runs_only_one_tty_session_without_log_capture(self):
        runner = mock.Mock(return_value=SimpleNamespace(returncode=0))
        with mock.patch.object(op.replica.operator, "single_operator", return_value=nullcontext()), \
             mock.patch.object(op.replica, "verified_container", return_value=CID), \
             mock.patch.object(op.replica, "run_mongosh", return_value="PRIMARY"):
            op.create_first_admin(confirm=lambda: None, runner=runner)
        runner.assert_called_once()
        args, kw = runner.call_args
        self.assertEqual(args[0], op.first_admin_argv(CID))
        self.assertEqual(kw, {"check": False, "timeout": 180})
        self.assertNotIn("capture_output", kw)
        self.assertNotIn("env", kw)
        self.assertNotIn("input", kw)
        self.assertNotIn("stdout", kw)
        self.assertNotIn("stderr", kw)

    def test_nonzero_and_timeout_not_retried_or_misreported(self):
        for side_effect in (
            SimpleNamespace(returncode=1),
            subprocess.TimeoutExpired(["docker"], timeout=180),
            OSError("private-key-secret-SHOULD-NOT-PRINT"),
        ):
            with self.subTest(side_effect=str(type(side_effect))), \
                 mock.patch.object(op.replica.operator, "single_operator",
                                   return_value=nullcontext()), \
                 mock.patch.object(op.replica, "verified_container", return_value=CID), \
                 mock.patch.object(op.replica, "run_mongosh", return_value="PRIMARY"):
                runner = mock.Mock(
                    side_effect=side_effect if isinstance(side_effect, Exception) else None,
                    return_value=side_effect if not isinstance(side_effect, Exception) else None,
                )
                with self.assertRaises(op.Refused):
                    op.create_first_admin(confirm=lambda: None, runner=runner)
                runner.assert_called_once()

    def test_safe_inspect_does_not_claim_admin_exists(self):
        with mock.patch.object(op.replica, "inspect", return_value="PRIMARY"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(op.main(["inspect"]), 0)
            self.assertIn("admin_state=not-verified", out.getvalue())
        with mock.patch.object(op.replica, "inspect", side_effect=Exception("secret-DO-NOT-PRINT")), \
             redirect_stderr(io.StringIO()) as err:
            self.assertEqual(op.main(["inspect"]), 1)
            self.assertNotIn("secret-", err.getvalue())

    def test_ci_creation_denied_without_docker(self):
        proc = subprocess.run(
            ["python3", "-I", str(ROOT / "host/identity-production-mongo-admin.py"),
             "create"], capture_output=True, text=True, timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CI": "true"},
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("IDENTITY_PRODUCTION_MONGO_FIRST_ADMIN_REFUSED", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_make_targets_are_local_only_not_automated_chain(self):
        make = (ROOT / "Makefile").read_text()
        for target, action in (
            ("identity-prod-mongo-admin-plan", "plan"),
            ("identity-prod-mongo-admin-inspect", "inspect"),
            ("identity-prod-mongo-admin-create", "create"),
        ):
            with self.subTest(target=target):
                proc = subprocess.run(["make", "--no-print-directory", "-n", target],
                                      cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("host/identity-production-mongo-admin.py " + action, proc.stdout)
                for forbidden in ("sudo ", "ssh ", "docker exec", "make identity-prod-mongo-apply"):
                    self.assertNotIn(forbidden, proc.stdout)
        self.assertNotIn("identity-prod-plan:\n\t@$(PYTHON) host/identity-production-mongo-admin.py", make)


if __name__ == "__main__":
    unittest.main()
