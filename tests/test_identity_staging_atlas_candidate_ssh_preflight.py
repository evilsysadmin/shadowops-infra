"""Offline contract and end-to-end mocked check of the *isolated* human SSH preflight.

Does not connect to the host or run Docker; test binaries are temporary stubs.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "host/check-identity-atlas-candidate-preflight-over-ssh.sh"
DIGEST = "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91"
SHA = "4a48dff49c4a77703c6f4b164120d3cef8e77e76"
STABLE = ("IDENTITY_ATLAS_HOST_DIAG operator=matched marker=trusted"
          " compose=trusted checkpoint=absent backup=fresh-metadata"
          " restore=matching-metadata container=atlas-healthy image_source=previous")


def executable(path, value):
    path.write_text(value)
    path.chmod(0o755)


class CandidateIsolatedPreflightTests(unittest.TestCase):
    def test_shell_contract(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=10)
        source = SCRIPT.read_text()
        for expected in (DIGEST, SHA, "stale-main", "dirty-checkout",
                         "inspect-identity-atlas-release-failure-over-ssh.sh",
                         "rollback_checkpoint=absent", "unsafe-preflight-state",
                         "postflight-state-unverified", "sudo --non-interactive $operator preflight",
                         "IDENTITY_ATLAS_PREFLIGHT_OK", "IDENTITY_ATLAS_PREFLIGHT_BLOCKED",
                         "ProxyCommand=cloudflared access ssh --hostname %h"):
            self.assertIn(expected, source)
        self.assertNotIn("shadowops-identity-atlas-deploy", source)
        self.assertNotIn("docker compose up", source)
        self.assertNotIn("docker rm", source)
        self.assertNotIn("atlas-active", source)
        self.assertNotIn("gh workflow run", source)
        self.assertNotIn("sudo --non-interactive bash", source)

    def run_mocked(self, *, ssh_receipt="success", first="safe", second="safe", args=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            (repo / "host").mkdir(parents=True)
            fake_script = repo / "host" / SCRIPT.name
            shutil.copyfile(SCRIPT, fake_script)
            inspect = repo / "host" / "inspect-identity-atlas-release-failure-over-ssh.sh"
            executable(inspect, "#!/usr/bin/env bash\n"
                       "set -euo pipefail\n"
                       "count=0\n"
                       'if [[ -f "$MOCK_INSPECT_COUNTER" ]]; then count="$(cat "$MOCK_INSPECT_COUNTER")"; fi\n'
                       'count="$((count+1))"\n'
                       'printf "%s" "$count" > "$MOCK_INSPECT_COUNTER"\n'
                       'if [[ "$count" == 1 ]]; then printf "%s\\n" "$MOCK_FIRST"; else printf "%s\\n" "$MOCK_SECOND"; fi\n')
            bindir = root / "bin"
            bindir.mkdir()
            executable(bindir / "git", """#!/usr/bin/env python3
import sys
args=sys.argv[1:]
if 'remote' in args:
    print('https://github.com/evilsysadmin/shadowops-infra.git')
elif 'status' in args:
    pass
elif 'rev-parse' in args:
    print('a'*40)
elif 'ls-remote' in args:
    print('a'*40+'\\trefs/heads/main')
else:
    sys.exit(1)
""")
            executable(bindir / "cloudflared", "#!/bin/sh\nexit 0\n")
            executable(bindir / "ssh", """#!/usr/bin/env python3
import os,sys
from pathlib import Path
Path(os.environ['MOCK_SSH_ARGS']).write_text(' '.join(sys.argv[1:]))
mode=os.environ['MOCK_SSH_RECEIPT']
if mode=='success':
    print('IDENTITY_ATLAS_PREFLIGHT_OK source_sha=' + os.environ['MOCK_SHA'] +
          ' digest=' + os.environ['MOCK_DIGEST'])
elif mode=='failure':
    print('IDENTITY_ATLAS_PREFLIGHT_BLOCKED type=PreflightError',file=sys.stderr)
    sys.exit(1)
elif mode=='secret':
    print('fatal: private configuration MY_SECRET must never reach the user',file=sys.stderr)
    sys.exit(1)
elif mode=='bad':
    print('INVALID UNKNOWN',file=sys.stderr)
else:
    sys.exit(1)
""")
            env = dict(os.environ)
            env.update({
                "PATH": str(bindir) + ":" + env["PATH"],
                "MOCK_SHA": SHA, "MOCK_DIGEST": DIGEST,
                "MOCK_SSH_ARGS": str(root / "ssh.txt"),
                "MOCK_INSPECT_COUNTER": str(root / "count"),
                "MOCK_FIRST": STABLE if first == "safe" else STABLE.replace("checkpoint=absent", "checkpoint=present"),
                "MOCK_SECOND": STABLE if second == "safe" else STABLE.replace("image_source=previous", "image_source=candidate"),
                "MOCK_SSH_RECEIPT": ssh_receipt,
            })
            result = subprocess.run(["bash", str(fake_script), *(args or [])],
                                    env=env, capture_output=True, text=True, timeout=20)
            ssh_args = (root / "ssh.txt").read_text() if (root / "ssh.txt").exists() else None
            inspections = int((root / "count").read_text()) if (root / "count").exists() else 0
            return result.returncode, result.stdout, result.stderr, ssh_args, inspections

    def test_expected_success_performs_one_pinned_preflight_and_two_state_checks(self):
        code, out, err, ssh, count = self.run_mocked()
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "IDENTITY_ATLAS_CANDIDATE_PREFLIGHT_OK live_identity=unchanged rollback_checkpoint=absent")
        self.assertEqual(count, 2)
        self.assertIn("sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-preflight preflight", ssh)
        self.assertIn(DIGEST, ssh)
        self.assertIn(SHA, ssh)
        self.assertNotIn("atlas-deploy", ssh)

    def test_unsafe_before_never_invokes_preflight(self):
        code, out, _, ssh, count = self.run_mocked(first="unsafe")
        self.assertNotEqual(code, 0)
        self.assertIn("unsafe-preflight-state", out + _)
        self.assertIsNone(ssh)
        self.assertEqual(count, 1)

    def test_failed_preflight_still_verifies_host_and_sanitizes_error(self):
        code, out, err, ssh, count = self.run_mocked(ssh_receipt="failure")
        self.assertNotEqual(code, 0)
        self.assertEqual(count, 2)
        self.assertIn("type=PreflightError", out + err)
        self.assertIsNotNone(ssh)

    def test_remote_secret_is_never_echoed(self):
        code, out, err, _, count = self.run_mocked(ssh_receipt="secret")
        self.assertNotEqual(code, 0)
        self.assertEqual(count, 2)
        self.assertIn("type=unknown", out + err)
        self.assertNotIn("MY_SECRET", out + err)

    def test_failed_postflight_is_fatal_even_when_preflight_returns_success(self):
        code, out, err, _, count = self.run_mocked(second="unsafe")
        self.assertNotEqual(code, 0)
        self.assertEqual(count, 2)
        self.assertIn("postflight-state-unverified", out + err)
        self.assertNotIn("CANDIDATE_PREFLIGHT_OK", out + err)

    def test_arguments_are_rejected_without_host_access(self):
        code, out, err, ssh, count = self.run_mocked(args=["override"])
        self.assertNotEqual(code, 0)
        self.assertIn("reason=arguments", out + err)
        self.assertIsNone(ssh)
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
