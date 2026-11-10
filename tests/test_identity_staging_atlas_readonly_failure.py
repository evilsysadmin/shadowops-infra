"""No-host/no-network contracts for the human Atlas SSH read-only failure inspector."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_atlas_readonly_failure as diag


class AtlasReadOnlyFailureTests(unittest.TestCase):
    def test_shell_syntax_and_ssh_sudo_are_read_only(self):
        path = ROOT / "host/inspect-identity-atlas-release-failure-over-ssh.sh"
        subprocess.run(["bash", "-n", str(path)], check=True, timeout=10)
        shell = path.read_text()
        self.assertIn("ssh-transport", shell)
        self.assertIn("sudo-or-readonly-probe", shell)
        self.assertIn("sudo --non-interactive python3 -I -", shell)
        self.assertIn("stale-checkout", shell)
        self.assertIn("unexpected-readonly-receipt", shell)
        self.assertNotIn("sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-deploy", shell)
        self.assertNotIn("gh workflow run", shell)
        self.assertNotIn("docker compose", shell)
        self.assertNotIn("rm -f", shell)

    def test_root_probe_never_mutates_containers_or_reads_secret_config(self):
        source = (ROOT / "scripts/identity_staging_atlas_readonly_failure.py").read_text()
        self.assertIn('["ps", "-aq"', source)
        self.assertIn('["inspect", "--type", "container"', source)
        self.assertIn('metadata(STATE / "atlas-active", private=True)', source)
        self.assertIn('checkpoint_status()', source)
        self.assertIn('backup_restore_metadata(datetime.now(timezone.utc))', source)
        self.assertNotIn('subprocess.run(["docker", "compose"', source)
        self.assertNotIn('"docker", "exec"', source)
        self.assertNotIn('"docker", "run"', source)
        self.assertNotIn('"docker", "pull"', source)
        self.assertNotIn("Config.Env", source)
        self.assertNotIn("log.stdout", source)

    def test_file_ownership_and_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "marker"
            self.assertEqual(diag.metadata(file), "missing")
            file.write_text("no secret")
            file.chmod(0o600)
            self.assertEqual(diag.metadata(file, private=True, expected_owner=__import__("os").getuid()), "trusted")
            file.chmod(0o644)
            self.assertEqual(diag.metadata(file, private=True, expected_owner=__import__("os").getuid()), "unsafe")
            file.unlink()
            file.symlink_to(Path(temp) / "missing-target")
            self.assertEqual(diag.metadata(file, expected_owner=__import__("os").getuid()), "unsafe")

    def test_backup_restore_freshness_and_matching_metadata_only(self):
        now = datetime.now(timezone.utc)
        backup = {
            "schema": 1, "backend": "atlas", "environment": "staging",
            "created_at": now.isoformat(),
            "sha256": "b" * 64, "cluster_sha256": "c" * 64,
        }
        restore = {
            "schema": 1, "backend": "atlas", "environment": "staging",
            "created_at": now.isoformat(), "result": "quarantine-restore-verified",
            "backup_sha256": "b" * 64, "cluster_sha256": "c" * 64,
        }
        with patch.object(diag, "read_receipt", side_effect=[backup, restore]):
            self.assertEqual(diag.backup_restore_metadata(now),
                             ("fresh-metadata", "matching-metadata"))
        with patch.object(diag, "read_receipt", side_effect=[backup, dict(restore, backup_sha256="d"*64)]):
            self.assertEqual(diag.backup_restore_metadata(now),
                             ("fresh-metadata", "unverified"))
        backup["created_at"] = (now - timedelta(hours=25)).isoformat()
        with patch.object(diag, "read_receipt", side_effect=[backup, restore]):
            self.assertEqual(diag.backup_restore_metadata(now), ("unverified", "unverified"))
        self.assertFalse(diag.freshness(dict(restore, created_at="not-a-date"), now))

    def test_docker_inspect_rejects_local_mount_and_unhealthy_container(self):
        image = "ghcr.io/evilsysadmin/shadowops-identity@sha256:" + "a" * 64
        labels = {
            "com.docker.compose.project": diag.PROJECT,
            "com.docker.compose.service": "identity",
            "org.opencontainers.image.source": "https://github.com/evilsysadmin/shadowops-infra",
            "org.opencontainers.image.revision": diag.OLD_SHA,
        }
        mounts = [{
            "Destination": "/run/secrets/identity-staging.json",
            "Source": "/etc/shadowops/identity-staging/atlas-service.json",
            "Type": "bind", "RW": False,
        }]
        networks = {diag.PROJECT + "-origin": {}, diag.PROJECT + "-atlas-egress": {}}
        payload = [image, labels, mounts, networks, "running", "healthy"]

        def docker(_):
            if len(_) > 0 and _[0] == "ps":
                return "a" * 64
            return "\t".join(json.dumps(v) for v in payload)

        with patch.object(diag, "docker", side_effect=docker):
            self.assertEqual(diag.container_status(), ("atlas-healthy", "previous"))
            payload[5] = "unhealthy"
            self.assertEqual(diag.container_status(), ("unhealthy", "previous"))
            payload[5] = "healthy"
            mounts[0]["Source"] = "/etc/shadowops/identity-staging/service.json"
            self.assertEqual(diag.container_status(), ("not-atlas", "previous"))
            mounts[0]["Source"] = "/etc/shadowops/identity-staging/atlas-service.json"
            payload[0] = "invalid"
            self.assertEqual(diag.container_status(), ("untrusted-image", "previous"))

    def test_inspector_only_returns_bounded_nonsecret_categories(self):
        with patch.object(diag.os, "geteuid", return_value=0), \
             patch.object(diag, "operator_status", return_value="matched"), \
             patch.object(diag, "metadata", return_value="trusted"), \
             patch.object(diag, "checkpoint_status", return_value="absent"), \
             patch.object(diag, "backup_restore_metadata", return_value=("fresh-metadata", "matching-metadata")), \
             patch.object(diag, "container_status", return_value=("atlas-healthy", "previous")):
            result = diag.inspect()
            self.assertIn("checkpoint=absent", result)
            self.assertIn("container=atlas-healthy", result)
            self.assertIn("image_source=previous", result)
            self.assertNotIn("sha256:", result)
            self.assertNotIn("/etc/", result)


if __name__ == "__main__":
    unittest.main()
