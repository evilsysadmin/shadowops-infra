"""Operator commands cannot install an arbitrary ref/host or mutate during inspect."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "host/bootstrap-cka-lab-over-ssh.sh"
SHA = "a" * 40


class OperatorMake(unittest.TestCase):
    def invoke(self, *, action="bootstrap", main=SHA, ssh_exit=0, key=None, make=False):
        with tempfile.TemporaryDirectory(prefix="cka-operator-test-") as folder:
            temporary = Path(folder)
            trace = temporary / "trace.json"
            body = temporary / "remote.sh"
            git_trace = temporary / "git-args.json"
            python = os.sys.executable
            for name, source in {
                "git": f"#!{python}\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['TEST_GIT_TRACE']).write_text(json.dumps(sys.argv[1:]))\nprint(os.environ['TEST_MAIN']+'\\trefs/heads/main')\n",
                "ssh": f"#!{python}\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['TEST_TRACE']).write_text(json.dumps(sys.argv[1:]))\nPath(os.environ['TEST_BODY']).write_text(sys.stdin.read())\nsys.exit(int(os.environ['TEST_SSH_EXIT']))\n",
                "cloudflared": "#!/bin/sh\nexit 0\n",
            }.items():
                executable = temporary / name
                executable.write_text(source)
                executable.chmod(0o755)
            env = dict(os.environ)
            env.pop("CKA_OPERATOR_SSH_KEY", None)
            env.update(PATH=str(temporary) + os.pathsep + env.get("PATH", ""),
                       TEST_MAIN=main, TEST_TRACE=str(trace), TEST_BODY=str(body),
                       TEST_GIT_TRACE=str(git_trace), TEST_SSH_EXIT=str(ssh_exit))
            if key is not None:
                env["CKA_OPERATOR_SSH_KEY"] = key
            args = ["make", "--no-print-directory", "cka-lab-" + action] if make else ["bash", str(SCRIPT), action]
            result = subprocess.run(args, cwd=ROOT, env=env, input="", capture_output=True,
                                    text=True, timeout=15)
            return (result, json.loads(trace.read_text()) if trace.exists() else [],
                    body.read_text() if body.exists() else "", git_trace.exists())

    def test_make_bootstrap_resolves_only_protected_main_and_runs_reviewed_install(self):
        result, args, body, git_called = self.invoke(make=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(git_called)
        self.assertEqual(args[-2], "ubuntu@ssh-chess-studio-staging.shadowops.dpdns.org")
        self.assertIn("ProxyCommand=cloudflared access ssh --hostname %h", args)
        self.assertIn("StrictHostKeyChecking=ask", args)
        self.assertEqual(args[-1], "sudo --non-interactive bash -se -- '" + SHA + "' 'bootstrap'")
        self.assertIn('rev-parse refs/remotes/origin/main', body)
        preflight = 'python3 -I host/install-cka-lab-staging.py preflight "$expected"'
        install = 'python3 -I host/install-cka-lab-staging.py install "$expected"'
        self.assertLess(body.index(preflight), body.index(install))
        self.assertIn("set -euo pipefail", body)
        # Validate the actual nested heredocs sent over SSH, without executing them.
        checked = subprocess.run(["bash", "-n"], input=body, text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("BOOTSTRAP_COMPLETED labs_enabled=false", result.stdout)

    def test_inspect_performs_one_fixed_read_without_git_or_install(self):
        result, args, body, git_called = self.invoke(action="inspect", make=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(git_called)
        self.assertEqual(body, "")
        self.assertEqual(args[-1], "sudo --non-interactive /usr/local/sbin/shadowops-cka-lab-staging inspect")
        self.assertNotIn("BOOTSTRAP_COMPLETED", result.stdout)

    def test_cluster_bootstrap_checks_installed_runtime_then_uses_fixed_kind_actions(self):
        result, args, body, git_called = self.invoke(action="cluster-bootstrap", make=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(git_called)
        self.assertEqual(args[-1], "sudo --non-interactive bash -se -- '" + SHA + "' 'cluster-bootstrap'")
        self.assertIn('rev-parse refs/remotes/origin/main', body)
        self.assertIn('/usr/local/sbin/shadowops-cka-lab-staging inspect >/dev/null', body)
        prefix = 'sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I scripts/cka_lab_cluster.py '
        positions = [body.index(prefix + verb) for verb in ('install-tools', 'bootstrap', 'verify-cluster')]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('if [[ "$action" == bootstrap ]]', body)
        self.assertIn('CKA_LAB_OPERATOR_CLUSTER_BOOTSTRAP_COMPLETED labs_enabled=false', result.stdout)
        parsed = subprocess.run(["bash", "-n"], input=body, text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_cluster_verify_is_read_only_and_never_fetches_or_bootstraps(self):
        result, args, body, git_called = self.invoke(action="cluster-verify", make=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(git_called)
        self.assertEqual(body, "")
        self.assertEqual(args[-1],
            'sudo --non-interactive /usr/local/sbin/shadowops-cka-lab-staging inspect >/dev/null'
            ' && sudo --non-interactive -u shadowops-cka-lab /usr/bin/python3 -I'
            ' /opt/shadowops-infra/scripts/cka_lab_cluster.py verify-cluster')
        self.assertNotIn("BOOTSTRAP_COMPLETED", result.stdout)
        self.assertNotIn("bootstrap", args[-1].lower())

    def test_invalid_source_or_action_never_reaches_ssh(self):
        for main in ["main", "b" * 39, SHA + ";echo injected", SHA + "\n" + SHA]:
            with self.subTest(main=main):
                result, args, _, _ = self.invoke(main=main)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(args, [])
        result, args, _, git_called = self.invoke(action="install;echo injected")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(args, [])
        self.assertFalse(git_called)

    def test_failed_ssh_never_reports_success(self):
        for action in ["bootstrap", "inspect", "cluster-bootstrap", "cluster-verify"]:
            with self.subTest(action=action):
                result, _, _, _ = self.invoke(action=action, ssh_exit=73, make=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("BOOTSTRAP_COMPLETED", result.stdout)

    def test_key_path_is_one_literal_argument_and_missing_or_symlink_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "operator $(do-not-execute) key"
            key.touch(mode=0o600)
            result, args, _, _ = self.invoke(key=str(key), make=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(args[args.index("-i") + 1], str(key))
            link = Path(folder) / "link"
            link.symlink_to(key)
            for invalid in [str(link), str(key) + "missing"]:
                result, args, _, git_called = self.invoke(key=invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(args, [])
                self.assertFalse(git_called)

    def test_default_make_only_prints_help(self):
        result = subprocess.run(["make", "--no-print-directory"], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("make cka-lab-bootstrap", result.stdout)
        self.assertIn("make cka-lab-inspect", result.stdout)
        self.assertIn("make cka-lab-cluster-bootstrap", result.stdout)
        self.assertIn("make cka-lab-cluster-verify", result.stdout)
        self.assertNotIn("bash host/", result.stdout)


if __name__ == "__main__":
    unittest.main()
