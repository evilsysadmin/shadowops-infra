"""Regression tests for secret-free Atlas release phase and rollback receipts.

The unit tests use only fake Docker and temporary checkpoint directories.
The SSH smoke uses a fake local git/ssh executable, never a remote host.
"""
import contextlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import test_identity_staging_atlas_release as base

release = base.release
SCRIPT = ROOT / "host/identity-staging-atlas-release-over-ssh.sh"


class RejectActivation(base.FakeRunner):
    def __call__(self, args, *, digest=None, timeout=180):
        if args[:2] == ["docker", "compose"] and "up" in args and digest == base.NEW:
            self.mutations.append(digest)
            raise RuntimeError("PRIVATE_ATLAS_SECRET_NOT_FOR_LOGS")
        return super().__call__(args, digest=digest, timeout=timeout)


class RejectAudience(base.FakeRunner):
    def __call__(self, args, *, digest=None, timeout=180):
        if args[0] == "curl" and args[-1].endswith("/login?app=snooker"):
            return "other audience"
        return super().__call__(args, digest=digest, timeout=timeout)


class BrokenPreflight(base.Preflight):
    def execute(self, digest, sha):
        raise ValueError("PRIVATE_MONGO_CREDENTIAL")


class TransitionStageTests(unittest.TestCase):
    def run_case(self, fake, *, preflight=None):
        progress = {"stage": "request", "rollback": "not-started"}
        with tempfile.TemporaryDirectory() as root:
            journal = release.TransitionCheckpoint(root, expected_uid=os.getuid())
            with patch.object(release, "root_file"), patch.object(
                release, "require_atlas_restore_evidence"
            ), patch.object(release, "validate_atlas_compose"):
                with self.assertRaises(Exception) as caught:
                    release.update(base.NEW, base.NEW_SHA, runner=fake,
                                   preflight=preflight or base.Preflight(),
                                   backup_operator=base.Backup(),
                                   check_shared=lambda: None, journal=journal,
                                   progress=progress)
            journal_pending = journal.path.exists()
        return caught.exception, progress, fake.mutations, journal_pending

    def test_failed_candidate_activate_records_original_stage_and_verified_rollback(self):
        exc, progress, changes, pending = self.run_case(RejectActivation())
        self.assertEqual(progress["failure"], "candidate-activation")
        self.assertEqual(progress["rollback"], "verified")
        self.assertEqual(changes, [base.NEW, base.OLD])
        self.assertFalse(pending)
        self.assertNotIn("PRIVATE_", str(exc))

    def test_candidate_public_outage_records_first_failure_even_after_rollback(self):
        exc, progress, changes, pending = self.run_case(base.FakeRunner(fail_candidate=True))
        self.assertEqual(progress["failure"], "candidate-public")
        self.assertEqual(progress["rollback"], "verified")
        self.assertEqual(changes, [base.NEW, base.OLD])
        self.assertFalse(pending)
        self.assertNotIn("PRIVATE_", str(exc))

    def test_candidate_audience_mismatch_records_audience_phase(self):
        exc, progress, changes, pending = self.run_case(RejectAudience())
        self.assertEqual(progress["failure"], "candidate-audience")
        self.assertEqual(progress["rollback"], "verified")
        self.assertEqual(changes, [base.NEW, base.OLD])
        self.assertFalse(pending)
        self.assertNotIn("PRIVATE_", str(exc))

    def test_failed_rollback_retains_checkpoint_and_records_unverified(self):
        _, progress, changes, pending = self.run_case(
            base.FakeRunner(fail_candidate=True, fail_previous=True))
        self.assertEqual(progress["failure"], "candidate-public")
        self.assertEqual(progress["rollback"], "unverified")
        self.assertEqual(changes, [base.NEW, base.OLD])
        self.assertTrue(pending)

    def test_failed_candidate_preflight_does_not_attempt_activation(self):
        _, progress, changes, pending = self.run_case(
            base.FakeRunner(), preflight=BrokenPreflight())
        self.assertEqual(progress["stage"], "candidate-preflight")
        self.assertEqual(progress["rollback"], "not-started")
        self.assertEqual(changes, [])
        self.assertFalse(pending)

    def test_main_sanitizes_private_exception_details(self):
        meta = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        err = io.StringIO()
        with patch.object(release.os, "geteuid", return_value=0), patch.object(
            release.sys, "argv", ["operator", "deploy", base.NEW, base.NEW_SHA]
        ), patch.object(release.os, "open", return_value=23), patch.object(
            release.os, "fstat", return_value=meta
        ), patch.object(release.os, "close"), patch.object(
            release.fcntl, "flock"
        ), patch.object(release, "update", side_effect=RuntimeError("PRIVATE_PASSWORD")), contextlib.redirect_stderr(err):
            result = release.main()
        self.assertEqual(result, 1)
        self.assertEqual(err.getvalue().strip(),
                         "IDENTITY_ATLAS_DEPLOY_BLOCKED type=RuntimeError stage=lock rollback=not-started")
        self.assertNotIn("PRIVATE_PASSWORD", err.getvalue())


def fake_executable(path, content):
    path.write_text(content)
    path.chmod(0o755)


class SshReceiptTests(unittest.TestCase):
    def run_ssh(self, remote_line):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            checkout = root / "checkout"
            (checkout / "host").mkdir(parents=True)
            local = checkout / "host" / SCRIPT.name
            shutil.copyfile(SCRIPT, local)
            binaries = root / "bin"
            binaries.mkdir()
            fake_executable(binaries / "git", StringGit)
            fake_executable(binaries / "ssh", """#!/usr/bin/env python3
import os,sys
print(os.environ['FAKE_SSH_LINE'],file=sys.stderr)
sys.exit(1)
""")
            fake_executable(binaries / "cloudflared", "#!/bin/sh\nexit 0\n")
            env = dict(os.environ, PATH=str(binaries) + ":" + os.environ["PATH"],
                       FAKE_REPO=str(checkout), FAKE_SSH_LINE=remote_line)
            p = subprocess.run(["bash", str(local)], env=env, text=True,
                               capture_output=True, timeout=20)
            return p.returncode, p.stdout + p.stderr

    def test_shell_syntax_and_sudo_command_unchanged(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=10)
        source = SCRIPT.read_text()
        self.assertIn("sudo --non-interactive $wrapper deploy $digest $source_sha", source)
        self.assertIn("2>&1", source)
        self.assertIn("rollback=(not-started|attempted|verified|unverified)", source)
        self.assertIn("IDENTITY_ATLAS_DEPLOY_BLOCKED type=", source)
        self.assertNotIn("sudo docker", source)
        self.assertNotIn("echo \"$receipt\" >&2", source)

    def test_allowed_fixed_stage_relayed(self):
        line = "IDENTITY_ATLAS_DEPLOY_BLOCKED type=AtlasTransitionBlocked stage=candidate-public rollback=verified"
        status, result = self.run_ssh(line)
        self.assertNotEqual(status, 0)
        self.assertEqual(result.strip(), line)

    def test_arbitrary_ssh_error_and_secret_discarded(self):
        status, result = self.run_ssh("Docker secret leaked: PASSWORD=PRIVATE_ATLAS_PASSWORD")
        self.assertNotEqual(status, 0)
        self.assertEqual(result.strip(), "IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=host-or-operator")
        self.assertNotIn("PRIVATE_ATLAS_PASSWORD", result)

    def test_extra_lines_or_unknown_stage_not_relayed(self):
        cases = [
            "warning\nIDENTITY_ATLAS_DEPLOY_BLOCKED type=AtlasReleaseBlocked stage=lock rollback=not-started",
            "IDENTITY_ATLAS_DEPLOY_BLOCKED type=RuntimeError stage=secret-key rollback=verified",
            "IDENTITY_ATLAS_DEPLOY_BLOCKED type=RuntimeError stage=rollback-public rollback=no",
        ]
        for item in cases:
            with self.subTest(item=item):
                status, result = self.run_ssh(item)
                self.assertNotEqual(status, 0)
                self.assertEqual(result.strip(), "IDENTITY_ATLAS_SSH_RELEASE_BLOCKED reason=host-or-operator")


StringGit = """#!/usr/bin/env python3
import os,sys
args=sys.argv[1:]
if args[:2] == ['rev-parse','--show-toplevel']:
    print(os.environ['FAKE_REPO'])
elif args[:2] == ['remote','get-url']:
    print('https://github.com/evilsysadmin/shadowops-infra.git')
elif 'status' in args:
    pass
elif args[:2] == ['rev-parse','HEAD']:
    print('a'*40)
elif args[0] == 'ls-remote':
    print('a'*40+'\\trefs/heads/main')
else:
    sys.exit(1)
"""


if __name__ == "__main__":
    unittest.main()
