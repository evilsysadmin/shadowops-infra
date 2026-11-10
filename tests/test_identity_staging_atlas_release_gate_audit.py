"""Offline-only validation of Atlas pre-activation inspection; NEVER connects to OCI."""
import ast
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_atlas_release_gate_audit as audit


class FakeRelease:
    STATE = Path("/faux/identity-state")
    ROOT = Path("/faux/identity-config")

    def __init__(self):
        self.calls = []
        self.previous = "sha256:" + "a" * 64
        self.previous_sha = audit.OLD_SHA
        self.public_sha = audit.OLD_SHA
        self.backups_valid = True
        self.shared_valid = True
        self.cached = True
        self.bad_cache = False
        self.invalid_compose = None

    def root_file(self, path, *, private=False):
        self.calls.append(("file", path.name, private))

    def require_atlas_restore_evidence(self, config, state):
        self.calls.append(("backup",))
        if not self.backups_valid:
            raise ValueError("sensitive backup error, never print this")

    def verify_shared_a1_containers(self):
        self.calls.append(("shared",))
        if not self.shared_valid:
            raise ValueError("sensitive shared host data, never print this")

    def live_image(self, runner):
        self.calls.append(("live",))
        return self.previous, self.previous_sha

    def public_release_sha(self, runner):
        self.calls.append(("public",))
        return self.public_sha

    def validate_atlas_compose(self, data, digest):
        self.calls.append(("compose_policy", digest))
        if digest == self.invalid_compose:
            raise ValueError("sensitive normalized compose data")

    def run(self, args, *, digest=None, timeout=180):
        self.calls.append(("run", tuple(args), digest))
        if args[:2] == ["docker", "compose"]:
            return '{"name":"synthetic"}'
        if args[:3] == ["docker", "image", "inspect"]:
            if not self.cached:
                raise RuntimeError("not cached")
            return ('{"org.opencontainers.image.revision":"'
                    + ("0" * 40 if self.bad_cache else audit.SOURCE_SHA)
                    + '","org.opencontainers.image.source":'
                      '"https://github.com/evilsysadmin/shadowops-infra"}')
        raise AssertionError("Unexpected Docker command")


class FakePreflight:
    def __init__(self):
        self.used = False

    def trusted_paths(self):
        self.used = True

    def execute(self, *args):
        raise AssertionError("preflight must never execute")


class FakeBackup:
    def private_config(self):
        return {"fake": "secret-never-printed"}


class GateAuditTests(unittest.TestCase):
    def setup(self, release=None):
        release = release or FakeRelease()
        preflight = FakePreflight()
        backup = FakeBackup()

        def loader(name, path):
            if name == "atlas_release_audit":
                return release
            if name == "atlas_preflight_audit":
                return preflight
            if name == "atlas_backup_audit":
                return backup
            raise AssertionError(name)

        return release, preflight, loader

    def run_audit(self, release=None):
        release, preflight, loader = self.setup(release)
        with patch.object(audit, "verify_authority"), patch.object(audit, "require_no_pending"):
            result = audit.evaluate(root_uid=lambda: 0, load=loader)
        self.assertTrue(preflight.used)
        return result, release

    def test_all_preactivation_gates_pass_without_any_mutation(self):
        result, release = self.run_audit()
        self.assertEqual(
            result, "IDENTITY_ATLAS_RELEASE_GATES_OK preactivation=verified"
                    " cached_candidate=matched candidate_preflight=not-run transition=not-attempted")
        commands = [item[1] for item in release.calls if item[0] == "run"]
        self.assertEqual(len(commands), 3)
        self.assertEqual(len([cmd for cmd in commands if cmd[:2] == ("docker", "compose")]), 2)
        self.assertEqual(len([cmd for cmd in commands if cmd[:3] == ("docker", "image", "inspect")]), 1)
        self.assertFalse(any("up" in cmd or "pull" in cmd or "run" in cmd or "rm" in cmd for cmd in commands))
        self.assertIn(("backup",), release.calls)
        self.assertIn(("shared",), release.calls)

    def test_missing_image_cache_is_not_mistaken_for_preflight_success(self):
        release = FakeRelease()
        release.cached = False
        result, _ = self.run_audit(release)
        self.assertIn("cached_candidate=not-cached", result)
        self.assertIn("candidate_preflight=not-run", result)

    def test_actual_backup_and_shared_host_gates_fail_closed(self):
        for target, gate in (("backups_valid", "backup-restore-crypto"),
                             ("shared_valid", "shared-host")):
            release, _, loader = self.setup()
            setattr(release, target, False)
            with self.subTest(gate=gate), patch.object(audit, "verify_authority"), patch.object(
                audit, "require_no_pending"
            ), self.assertRaises(audit.GateBlocked) as raised:
                audit.evaluate(root_uid=lambda: 0, load=loader)
            self.assertEqual(raised.exception.stage, gate)
            self.assertNotIn("secret", str(raised.exception))

    def test_public_and_compose_mismatch_cannot_be_ignored(self):
        for field, value, expected in (
            ("public_sha", "f" * 40, "public-source"),
            ("invalid_compose", audit.DIGEST, "compose-candidate"),
            ("bad_cache", True, "candidate-cache"),
            ("previous_sha", "0" * 40, "live-container"),
        ):
            release, _, loader = self.setup()
            setattr(release, field, value)
            with self.subTest(field=field), patch.object(audit, "verify_authority"), patch.object(
                audit, "require_no_pending"
            ), self.assertRaises(audit.GateBlocked) as raised:
                audit.evaluate(root_uid=lambda: 0, load=loader)
            self.assertEqual(raised.exception.stage, expected)

    def test_pending_checkpoint_refuses_before_any_host_operation(self):
        with patch.object(audit, "verify_authority"), patch.object(
            audit, "require_no_pending", side_effect=ValueError("pending")
        ), self.assertRaises(audit.GateBlocked) as raised:
            audit.evaluate(root_uid=lambda: 0, load=lambda *args: self.fail("must not load"))
        self.assertEqual(raised.exception.stage, "checkpoint")

    def test_nonroot_rejected_before_any_host_operation(self):
        with self.assertRaises(audit.GateBlocked) as raised:
            audit.evaluate(root_uid=lambda: 1000, load=lambda *args: self.fail("must not load"))
        self.assertEqual(raised.exception.stage, "authority")

    def test_shell_syntax_and_fixed_readonly_ssh_route(self):
        path = ROOT / "host/inspect-identity-atlas-release-gates-over-ssh.sh"
        subprocess.run(["bash", "-n", str(path)], timeout=10, check=True)
        content = path.read_text()
        self.assertIn("sudo --non-interactive /opt/shadowops/oci-venv/bin/python -I -", content)
        self.assertIn("ProxyCommand=cloudflared access ssh --hostname %h", content)
        self.assertIn("stale-main", content)
        self.assertIn("candidate_preflight=not-run transition=not-attempted", content)
        self.assertNotIn("shadowops-identity-atlas-deploy deploy", content)
        self.assertNotIn("rm -f", content)
        self.assertNotIn("docker compose up", content)

    def test_python_source_has_no_host_mutations_or_release_operator_execution(self):
        code = (ROOT / "scripts/identity_staging_atlas_release_gate_audit.py").read_text()
        tree = ast.parse(code)
        method_calls = [n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute)]
        for prohibited in ("update", "execute", "guarded_transition", "write_text",
                           "write_bytes", "unlink", "rename", "replace", "mkdir"):
            self.assertNotIn(prohibited, method_calls)
        self.assertNotIn("subprocess", code)
        self.assertNotIn("docker run", code)
        self.assertNotIn('"pull"', code)
        self.assertIn("backup-restore-crypto", code)
        self.assertIn("compose-candidate", code)


if __name__ == "__main__":
    unittest.main()
