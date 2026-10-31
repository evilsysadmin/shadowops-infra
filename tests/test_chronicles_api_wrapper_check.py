"""Read-only check of installed Chronicles API wrapper (no network or OCI)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "host/bootstrap-chronicles-api-over-ssh.sh"
SHA = "a" * 40


class WrapperCheckContracts(unittest.TestCase):
    @staticmethod
    def remote_script():
        code = SCRIPT.read_text(encoding="utf-8")
        return code.split("<<'REMOTE_CHECK'\n", 1)[1].split("\nREMOTE_CHECK", 1)[0]

    def test_remote_check_cannot_mutate_host(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        remote = self.remote_script()
        self.assertIn("readonly helper=/usr/local/sbin/shadowops-chronicles-api", remote)
        self.assertIn('sha256sum -- "$helper"', remote)
        for value in ("CURRENT", "OUTDATED", "MISSING", "UNSAFE"):
            self.assertIn("CHRONICLES_API_WRAPPER_" + value, remote)
        for word in ("sudo ", "docker ", "git ", "curl ", "install ", "chmod ",
                     "chown ", "systemctl ", "rm ", "mv ", "cp ", "fetch "):
            self.assertNotIn(word, remote)

    def test_check_mode_uses_pinned_hash_without_operator_sudo(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            for name, content in (
                ("git", 'printf "%s\trefs/heads/main\n" "$FAKE_MAIN"'),
                ("curl", "printf 'trusted-source-bytes'"),
                ("cloudflared", "exit 70"),
                ("ssh", 'printf "%s\n" "$*" > "$SSH_ARGS"; cat > "$SSH_BODY"'),
            ):
                path = p / name
                path.write_text("#!/bin/bash\n" + content + "\n")
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(p) + os.pathsep + os.environ["PATH"],
                       FAKE_MAIN=SHA, SSH_ARGS=str(p / "args"), SSH_BODY=str(p / "body"))
            result = subprocess.run(["bash", str(SCRIPT), "--check", SHA],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            digest = hashlib.sha256(b"trusted-source-bytes").hexdigest()
            arguments = (p / "args").read_text()
            self.assertIn("bash -se -- '" + digest + "'", arguments)
            self.assertNotIn("sudo", arguments)
            self.assertNotIn("deploy", arguments)
            self.assertNotIn("install-chronicles-api.sh", (p / "body").read_text())
            # Default path must remain the explicit privileged installation.
            normal = subprocess.run(["bash", str(SCRIPT), SHA],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(normal.returncode, 0, normal.stderr)
            install_args = (p / "args").read_text()
            self.assertIn("sudo --non-interactive bash -se -- '" + SHA + "'", install_args)
            self.assertIn('exec "$repo/host/install-chronicles-api.sh"',
                          (p / "body").read_text())
            for args in (["--check", "invalid"], [SHA, "--check"],
                         ["--check", SHA, SHA]):
                denied = subprocess.run(["bash", str(SCRIPT), *args],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(denied.returncode, 64, denied.stderr)

    def test_remote_statuses_are_read_only(self):
        remote_source = self.remote_script()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wrapper = root / "wrapper"
            wrapper.write_text("synthetic wrapper")
            wrapper.chmod(0o755)
            digest = hashlib.sha256(wrapper.read_bytes()).hexdigest()
            remote = remote_source.replace(
                "readonly helper=/usr/local/sbin/shadowops-chronicles-api",
                "readonly helper=" + str(wrapper))
            stat = root / "stat"
            stat.write_text('#!/bin/bash\n'
                            'if [[ "$2" == "%u" ]]; then echo 0; else echo "$FAKE_MODE"; fi\n')
            stat.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            def run(d=digest, mode="755"):
                return subprocess.run(["bash", "-se", "--", d], input=remote,
                                      capture_output=True, text=True,
                                      env=dict(env, FAKE_MODE=mode))
            for d, mode, code, message in (
                (digest, "755", 0, "CURRENT"),
                ("b" * 64, "755", 3, "OUTDATED"),
                (digest, "777", 65, "UNSAFE"),
            ):
                result = run(d, mode)
                self.assertEqual((result.returncode, result.stdout.strip()),
                                 (code, "CHRONICLES_API_WRAPPER_" + message), result.stderr)
            self.assertEqual(wrapper.read_text(), "synthetic wrapper")
            wrapper.unlink()
            missing = run()
            self.assertEqual((missing.returncode, missing.stdout.strip()),
                             (3, "CHRONICLES_API_WRAPPER_MISSING"), missing.stderr)


if __name__ == "__main__":
    unittest.main()
