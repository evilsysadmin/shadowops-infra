"""Offline safety tests for transplanted OCI A1 Cloudflare Access SSH."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("infra_a1_ssh", ROOT / "scripts/oci_a1_ssh.py")
a1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a1)


class A1SshTests(unittest.TestCase):
    def test_make_targets_exist_and_do_not_require_oci_cli(self):
        for target, action in (("oci-a1-ssh-check", "check"), ("oci-a1-ssh", "ssh")):
            with self.subTest(target=target):
                p = subprocess.run(["make", "-n", "--no-print-directory", target], cwd=ROOT,
                                   capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("scripts/oci_a1_ssh.py " + action, p.stdout)
                for forbidden in ("sudo ", "docker ", "oci session", "oci-a1-authorize",
                                  "ssh-chess-studio-staging.shadowops.dpdns.org;"):
                    self.assertNotIn(forbidden, p.stdout)
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("OCI_SSH_KEY ?=", makefile)
        self.assertIn("export OCI_SSH_USER OCI_SSH_KEY OCI_SSH_HOSTNAME", makefile)

    def test_default_ssh_settings_are_existing_a1(self):
        self.assertEqual(
            a1.operator_settings({}),
            ("ssh-chess-studio-staging.shadowops.dpdns.org", "ubuntu", ""),
        )
        with self.assertRaises(a1.Refused):
            a1.operator_settings({"OCI_SSH_HOSTNAME": "staging.evil.example"})
        with self.assertRaises(a1.Refused):
            a1.operator_settings({"OCI_SSH_USER": "root"})

    def test_key_is_local_private_regular_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "id_a1"
            key.write_text("fixture-private-key-not-real")
            key.chmod(0o600)
            self.assertEqual(a1.operator_settings({"OCI_SSH_KEY": str(key)})[2], str(key))
            key.chmod(0o644)
            with self.assertRaises(a1.Refused):
                a1.operator_settings({"OCI_SSH_KEY": str(key)})
            key.chmod(0o600)
            alias = Path(tmp) / "alias"
            alias.symlink_to(key)
            with self.assertRaises(a1.Refused):
                a1.operator_settings({"OCI_SSH_KEY": str(alias)})
            with self.assertRaises(a1.Refused):
                a1.operator_settings({"OCI_SSH_KEY": str(Path(tmp))})
            with self.assertRaises(a1.Refused):
                a1.operator_settings({"OCI_SSH_KEY": str(key) + "\nmalicious"})

    def test_ssh_uses_only_fixed_cloudflare_proxy_and_no_sudo(self):
        cmd = a1.command("/tmp/path with spaces/cloudflared", "/usr/bin/ssh",
                         a1.SSH_HOST, a1.SSH_USER, "/tmp/key")
        self.assertEqual(cmd[0], "/usr/bin/ssh")
        self.assertIn("ProxyCommand='/tmp/path with spaces/cloudflared' access ssh --hostname %h", cmd)
        self.assertIn("StrictHostKeyChecking=ask", cmd)
        self.assertIn("IdentitiesOnly=yes", cmd)
        self.assertEqual(cmd[-1], "ubuntu@" + a1.SSH_HOST)
        self.assertIn("/tmp/key", cmd)
        self.assertNotIn("sudo", cmd)
        self.assertNotIn("StrictHostKeyChecking=no", cmd)

    def test_status_check_is_safe_no_exec_no_remote_commands(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(a1.shutil, "which", side_effect=lambda x: "/usr/bin/" + x), \
             patch.object(a1, "check_edge_tls", return_value="TLSv1.3"), \
             patch.object(a1.os, "execv") as execv, \
             redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(a1.main(["check"], {}), 0)
        self.assertIn("OCI_A1_SSH_CHECK_OK edge_only=yes host_login=not-verified", out.getvalue())
        self.assertIn(a1.SSH_HOST, err.getvalue())
        execv.assert_not_called()

    def test_interactive_login_preserves_keys_and_execs_local_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "id_a1"
            key.write_text("test-only")
            key.chmod(0o600)
            env = {"OCI_SSH_KEY": str(key)}
            with patch.object(a1.shutil, "which", side_effect=lambda x: "/usr/bin/" + x), \
                 patch.object(a1, "check_edge_tls", return_value="TLSv1.3"), \
                 patch.object(a1.sys, "stdin") as stdin, \
                 patch.object(a1.os, "execv", side_effect=SystemExit(99)) as execv:
                stdin.isatty.return_value = True
                with self.assertRaises(SystemExit) as raised:
                    a1.main(["ssh"], env)
                self.assertEqual(raised.exception.code, 99)
            argv = execv.call_args.args
            self.assertEqual(argv[0], "/usr/bin/ssh")
            self.assertIn(str(key), argv[1])
            self.assertEqual(argv[1][-1], "ubuntu@" + a1.SSH_HOST)

    def test_ssh_ci_and_non_tty_denied_before_network(self):
        for env, tty in (({"CI": "true"}, True), ({"GITHUB_ACTIONS": "true"}, True),
                         ({}, False)):
            with self.subTest(env=env, tty=tty), \
                 patch.object(a1.sys, "stdin") as stdin, \
                 patch.object(a1, "check_edge_tls") as tls, \
                 patch.object(a1.os, "execv") as execv, \
                 redirect_stderr(io.StringIO()):
                stdin.isatty.return_value = tty
                self.assertEqual(a1.main(["ssh"], env), 1)
                tls.assert_not_called()
                execv.assert_not_called()

    def test_missing_client_and_invalid_target_fail_without_network(self):
        with patch.object(a1.shutil, "which", return_value=None), \
             patch.object(a1, "check_edge_tls") as tls, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(a1.main(["check"], {}), 1)
            tls.assert_not_called()
        with patch.object(a1, "check_edge_tls") as tls, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(a1.main(["check"], {"OCI_SSH_HOSTNAME": "other.example"}), 1)
            tls.assert_not_called()

    def test_invalid_cli_rejected(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(a1.main(["deploy"]), 2)


if __name__ == "__main__":
    unittest.main()
