"""Offline proof that operator bootstrap cannot target another host or mutable ref."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "host/bootstrap-chronicles-web-over-ssh.sh"
SHA = "c" * 40


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, arg, *, main=SHA, key=""):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trace = root / "ssh-args"
            remote = root / "ssh-stdin"
            for cmd, content in {
                "git": "#!/bin/sh\ncase \"$1\" in ls-remote) printf '%s\\trefs/heads/main\\n' \"$TEST_MAIN_SHA\" ;; *) exit 81 ;; esac\n",
                "ssh": "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_SSH_TRACE\"\ncat > \"$TEST_SSH_REMOTE\"\n",
                "cloudflared": "#!/bin/sh\nexit 0\n",
            }.items():
                executable = root / cmd
                executable.write_text(content)
                executable.chmod(0o755)
            env = dict(os.environ)
            env.update({
                "PATH": str(root) + os.pathsep + env.get("PATH", ""),
                "TEST_MAIN_SHA": main,
                "TEST_SSH_TRACE": str(trace),
                "TEST_SSH_REMOTE": str(remote),
            })
            if key:
                env["CHRONICLES_OPERATOR_SSH_KEY"] = key
            result = subprocess.run(["bash", str(SCRIPT), arg], env=env,
                                    capture_output=True, text=True, timeout=15)
            return result, trace.read_text() if trace.exists() else "", remote.read_text() if remote.exists() else ""

    def test_only_exact_main_sha_reaches_fixed_cloudflare_ssh(self):
        result, args, body = self.run_bootstrap(SHA)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org", args)
        self.assertIn("cloudflared access ssh --hostname %h", args)
        self.assertIn("sudo --non-interactive bash -se -- '" + SHA + "'", args)
        self.assertIn("ssh-chess-studio-staging.shadowops.dpdns.org", args)
        self.assertIn("rev-parse refs/remotes/origin/main", body)
        self.assertIn('git clone --no-tags --depth=1 --branch main "$origin" "$repo"', body)
        self.assertIn('exec "$repo/host/install-chronicles-web.sh" "$expected"', body)
        self.assertIn('[[ "$remote_main" != "$expected" ]]', body)
        self.assertNotIn("StrictHostKeyChecking=no", args + body)
        self.assertNotIn("docker ", body)
        self.assertNotIn("chess-studio-deploy", body)

    def test_reject_invalid_or_stale_hash_without_ssh(self):
        for arg, main in (
            ("main", SHA), (SHA + ";echo bad", SHA), ("", SHA),
            ("a" * 39, SHA), (SHA, "d" * 40),
        ):
            with self.subTest(arg=arg):
                result, args, body = self.run_bootstrap(arg, main=main)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(args)
                self.assertFalse(body)

    def test_missing_private_key_never_invokes_ssh(self):
        result, args, body = self.run_bootstrap(SHA, key="/nonexistent/path")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(args)
        self.assertFalse(body)

    def test_shell_syntax_and_no_private_keys_in_ci(self):
        checked = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        source = SCRIPT.read_text()
        self.assertNotIn("ssh-keyscan", source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertNotIn("usermod", source)
        self.assertNotIn("OCI_PRIVATE_KEY", source)
        self.assertNotIn("curl | bash", source)
        workflow = (ROOT / ".github/workflows/chronicles-web-runtime.yml").read_text()
        self.assertIn("test_chronicles_web_operator_bootstrap.py", workflow)


if __name__ == "__main__":
    unittest.main()
