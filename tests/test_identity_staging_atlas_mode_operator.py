from __future__ import annotations

import io
import json
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_atlas_mode_operator as mode


class Marker:
    def __init__(self, present):
        self.present = present

    def lstat(self):
        if not self.present:
            raise FileNotFoundError()
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=0)


def fake_docker(*, source=mode.LOCAL_CONFIG, networks=None, state="running",
                ids=None, mounts=None, fail=False):
    calls = []
    if networks is None:
        networks = {"shadowops-identity-staging-origin": {},
                    "shadowops-identity-staging-database": {}}
    if ids is None:
        ids = ["a" * 12]
    if mounts is None:
        mounts = [{"Destination": mode.CONFIG_DESTINATION, "Source": source,
                   "Type": "bind", "RW": False}]

    def runner(args, **kwargs):
        calls.append(args)
        assert args[0] == "docker" and kwargs["timeout"] == 8
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
        if fail:
            return SimpleNamespace(returncode=1, stdout="", stderr="PRIVATE password")
        if args[1] == "ps":
            assert args[2:] == [
                "-aq", "--filter",
                "label=com.docker.compose.project=shadowops-identity-staging",
                "--filter", "label=com.docker.compose.service=identity",
            ]
            value = "\n".join(ids)
        elif args[1] == "inspect":
            assert args[2:5] == ["--type", "container", "--format"]
            assert args[5] == "a" * 12
            value = {
                "{{json .Mounts}}": json.dumps(mounts),
                "{{json .NetworkSettings.Networks}}": json.dumps(networks),
                "{{.State.Status}}": state,
            }[args[4]]
        else:
            raise AssertionError("Unexpected Docker authority")
        return SimpleNamespace(returncode=0, stdout=value)

    return runner, calls


class AtlasOperatorModeTests(unittest.TestCase):
    def test_local_mounted_service_with_present_atlas_marker_is_reported_not_changed(self):
        run, calls = fake_docker()
        result = mode.inspect_mode(marker=Marker(True), runner=run, uid=lambda: 0)
        self.assertEqual(result,
            "IDENTITY_ATLAS_MODE marker=present config=local container=running")
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(args[1] in {"ps", "inspect"} for args in calls))
        self.assertFalse(any("logs" in item or "exec" in item or "env" in item
                             for args in calls for item in args))

    def test_atlas_mounted_service_is_distinct_from_local(self):
        run, _ = fake_docker(
            source=mode.ATLAS_CONFIG,
            networks={"shadowops-identity-staging-origin": {},
                      "shadowops-identity-staging-atlas-egress": {}},
        )
        self.assertEqual(
            mode.inspect_mode(marker=Marker(True), runner=run, uid=lambda: 0),
            "IDENTITY_ATLAS_MODE marker=present config=atlas container=running",
        )

    def test_missing_marker_and_stopped_container_are_not_declared_live(self):
        run, _ = fake_docker(state="exited")
        self.assertEqual(
            mode.inspect_mode(marker=Marker(False), runner=run, uid=lambda: 0),
            "IDENTITY_ATLAS_MODE marker=absent config=local container=exited",
        )

    def test_unrecognized_mount_network_or_container_fails_closed(self):
        cases = [
            {"source": "/tmp/private-config"},
            {"mounts": [{"Destination": mode.CONFIG_DESTINATION,
                         "Source": mode.LOCAL_CONFIG, "Type": "bind", "RW": True}]},
            {"mounts": [{"Destination": mode.CONFIG_DESTINATION,
                         "Source": mode.LOCAL_CONFIG, "Type": "bind", "RW": False}] * 2},
            {"networks": {"shadowops-identity-staging-origin": {},
                          "shadowops-identity-staging-database": {},
                          "shadowops-identity-staging-atlas-egress": {}}},
            {"ids": []},
            {"ids": ["invalid-id"]},
            {"state": "secret"},
            {"fail": True},
        ]
        for spec in cases:
            with self.subTest(spec=spec):
                run, _ = fake_docker(**spec)
                with self.assertRaises(mode.ModeError) as problem:
                    mode.inspect_mode(marker=Marker(True), runner=run, uid=lambda: 0)
                self.assertIn(problem.exception.reason,
                              {"docker", "identity-ambiguous", "mount-ambiguous",
                               "network-ambiguous", "state-ambiguous"})
                self.assertNotIn("password", str(problem.exception))

    def test_marker_symlink_or_wrong_owner_is_not_trusted(self):
        for st_mode, owner in ((stat.S_IFLNK | 0o777, 0),
                               (stat.S_IFREG | 0o400, 1001),
                               (stat.S_IFREG | 0o666, 0)):
            marker = SimpleNamespace(lstat=lambda: SimpleNamespace(
                st_mode=st_mode, st_uid=owner))
            run, calls = fake_docker()
            with self.assertRaises(mode.ModeError) as problem:
                mode.inspect_mode(marker=marker, runner=run, uid=lambda: 0)
            self.assertEqual(problem.exception.reason, "marker-unsafe")
            self.assertEqual(calls, [])

    def test_unprivileged_execution_cannot_inspect_docker(self):
        run, calls = fake_docker()
        self.assertEqual(
            mode.inspect_mode(marker=Marker(True), runner=run, uid=lambda: 1001),
            "IDENTITY_ATLAS_MODE_BLOCKED reason=not-root",
        )
        self.assertEqual(calls, [])

    def test_cli_returns_only_finite_errors_not_private_exception(self):
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["probe"]), \
             patch.object(mode.os, "geteuid", return_value=0), \
             patch.object(mode, "inspect_mode",
                          side_effect=mode.ModeError("network-ambiguous")), \
             redirect_stdout(stdout):
            self.assertEqual(mode.main(), 1)
        self.assertEqual(stdout.getvalue().strip(),
                         "IDENTITY_ATLAS_MODE_BLOCKED reason=network-ambiguous")

    def test_operator_ssh_script_is_parseable_without_network(self):
        result = subprocess.run(
            ["bash", "-n", str(ROOT / "host/inspect-identity-atlas-mode-over-ssh.sh")],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
