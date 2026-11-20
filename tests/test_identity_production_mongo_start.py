"""Mongo first-start operator: offline Docker doubles, no OCI/host writes."""
from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_start",
    ROOT / "host/identity-production-mongo-start.py",
)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
CID = "a" * 64
DIGEST = "sha256:" + "b" * 64


class DockerDouble:
    def __init__(self):
        self.calls = []
        self.running = False
        self.existing = ""
        self.existing_volume = ""
        self.existing_network = ""
        self.start_error = False
        self.rogue = False
        self.image = {
            "Architecture": "arm64", "Os": "linux",
            "Id": DIGEST, "RepoDigests": [op.host.IMAGE],
        }
        self.rendered = {
            "name": op.PROJECT,
            "services": {op.SERVICE: {
                "image": op.host.IMAGE, "user": "999:999",
                "read_only": True, "privileged": False,
                "restart": "no", "networks": {"identity-mongo-egress": {}},
            }},
            "volumes": {"identity-production-data": {"name": op.VOLUME}},
            "networks": {"identity-mongo-egress": {
                "name": op.NETWORK, "internal": True}},
        }
        self.runtime = {
            "Name": "/" + op.CONTAINER,
            "Config": {
                "Image": op.host.IMAGE, "User": "999:999",
                "Labels": op.CONTAINER_LABELS.copy(),
            },
            "State": {"Running": True, "Health": {"Status": "starting"}},
            "HostConfig": {
                "ReadonlyRootfs": True, "Privileged": False, "PortBindings": {},
            },
            "NetworkSettings": {"Networks": {op.NETWORK: {}}},
            "Mounts": [
                {"Destination": "/data/db", "Type": "volume", "Name": op.VOLUME},
                {"Destination": "/run/mongo", "Source": str(op.host.SECRET_DIR),
                 "RW": False},
            ],
        }

    def __call__(self, cmd, **kwargs):
        self.calls.append(tuple(cmd))
        assert cmd[0] == "docker", cmd
        args = cmd[1:]
        output = ""
        rc = 0
        if args[:2] == ["info", "--format"]:
            output = "27.0.2"
        elif args[:3] == ["image", "inspect", "--format"]:
            output = json.dumps(self.image)
        elif args[:2] == ["ps", "-a"]:
            output = (CID if self.running else self.existing)
        elif args[:2] == ["volume", "ls"]:
            output = self.existing_volume
        elif args[:2] == ["network", "ls"]:
            output = self.existing_network
        elif args[0] == "compose":
            if "config" in args:
                output = json.dumps(self.rendered)
            elif "up" in args:
                self.running = True
                if self.start_error:
                    rc = 1
            elif "stop" in args:
                self.running = False
            else:
                raise AssertionError("unexpected Compose verb: " + repr(args))
        elif args[:2] == ["inspect", "--format"]:
            output = json.dumps(self.runtime)
        else:
            raise AssertionError("unexpected Docker invocation: " + repr(args))
        return SimpleNamespace(stdout=output, stderr="sensitive test fixture",
                               returncode=rc)


class StartOperatorTests(unittest.TestCase):
    def setUp(self):
        # Mocked unit tests are offline but the real operator remains CI-denied.
        self.env = mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_no_credentials_no_docker_plan(self):
        with mock.patch.object(op, "docker", side_effect=AssertionError("Docker used")):
            self.assertEqual(op.main(["plan"]), 0)
            self.assertEqual(op.main(["unknown"]), 2)

    def test_initial_preflight_exact_empty_project(self):
        double = DockerDouble()
        with mock.patch.object(op.host, "inspect_private_files"):
            op.preflight(runner=double)
        self.assertFalse(any("up" in args or "pull" in args for args in double.calls))

    def test_deny_adopting_existing_state(self):
        for mutation in (
            lambda d: setattr(d, "existing", CID),
            lambda d: setattr(d, "existing_volume", op.VOLUME),
            lambda d: setattr(d, "existing_network", op.NETWORK),
        ):
            d = DockerDouble()
            mutation(d)
            with mock.patch.object(op.host, "inspect_private_files"), \
                 self.assertRaises(op.Refused):
                op.preflight(runner=d)
            self.assertFalse(any("up" in x for x in d.calls))

    def test_wrong_arch_or_untagged_image_fails_without_mongo_mutations(self):
        for poison in ("arch", "repo", "missing", "os"):
            d = DockerDouble()
            if poison == "arch":
                d.image["Architecture"] = "amd64"
            elif poison == "repo":
                d.image["RepoDigests"] = ["mongo@sha256:" + "0" * 64]
            elif poison == "os":
                d.image["Os"] = "windows"
            elif poison == "missing":
                d.image["Id"] = None
            with self.subTest(poison=poison), \
                 mock.patch.object(op.host, "inspect_private_files"), \
                 self.assertRaises(op.Refused):
                op.preflight(runner=d)
            self.assertFalse(any("up" in x for x in d.calls))

    def test_deny_exposed_port_or_foreign_network(self):
        for path in ("ports", "network", "volume", "staging"):
            d = DockerDouble()
            s = d.rendered["services"][op.SERVICE]
            if path == "ports":
                s["ports"] = [{"published": "27017"}]
            elif path == "network":
                d.rendered["networks"]["identity-mongo-egress"]["internal"] = False
            elif path == "volume":
                d.rendered["volumes"]["identity-production-data"]["name"] = "staging-volume"
            elif path == "staging":
                s["image"] = "mongo:latest"
            with self.subTest(path=path), \
                 mock.patch.object(op.host, "inspect_private_files"), \
                 self.assertRaises(op.Refused):
                op.preflight(runner=d)

    def test_interactive_gate_denies_ci_wrong_ack_and_unprivileged(self):
        with mock.patch.dict(os.environ, {"CI": "true"}):
            with self.assertRaises(op.Refused):
                op.manual_approval()
        with mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}), \
             mock.patch.object(op.os, "geteuid", return_value=1001):
            with self.assertRaises(op.Refused):
                op.manual_approval()
        with mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}), \
             mock.patch.object(op.os, "geteuid", return_value=0), \
             mock.patch.object(op.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="NOT_APPROVED"):
            with self.assertRaises(op.Refused):
                op.manual_approval()

    def test_exact_first_start_without_pull_build_or_dependencies(self):
        d = DockerDouble()
        with mock.patch.object(op, "manual_approval"), \
             mock.patch.object(op, "single_operator", return_value=nullcontext()), \
             mock.patch.object(op.host, "inspect_private_files"):
            op.start(runner=d)
        up = [x for x in d.calls if "up" in x]
        self.assertEqual(len(up), 1)
        self.assertEqual(up[0][-1], op.SERVICE)
        for required in ("--no-build", "--no-deps", "--pull", "never", "--detach"):
            self.assertIn(required, up[0])
        for call in d.calls:
            self.assertNotIn(call[1], ("down", "rm", "prune", "pull"))
            if call[1] == "compose":
                self.assertFalse(any(arg in ("down", "rm", "prune", "-v",
                                            "identity-production-tunnel")
                                     for arg in call[2:]))
        self.assertFalse(any("stop" in x for x in d.calls))

    def test_partial_start_and_rogue_container_rollback_scope(self):
        for problem in ("up-failure", "port", "staging-label", "network"):
            d = DockerDouble()
            if problem == "up-failure":
                d.start_error = True
            elif problem == "port":
                d.runtime["HostConfig"]["PortBindings"] = {"27017/tcp": [{"HostPort": "27017"}]}
            elif problem == "staging-label":
                d.runtime["Config"]["Labels"]["com.docker.compose.project"] = "shadowops-identity-staging"
            elif problem == "network":
                d.runtime["NetworkSettings"]["Networks"]["shadowops-identity-staging-database"] = {}
            with self.subTest(problem=problem), \
                 mock.patch.object(op, "manual_approval"), \
                 mock.patch.object(op, "single_operator", return_value=nullcontext()), \
                 mock.patch.object(op.host, "inspect_private_files"), \
                 self.assertRaises(op.Refused):
                op.start(runner=d)
            stops = [x for x in d.calls if "stop" in x]
            self.assertEqual(len(stops), 1)
            self.assertEqual(stops[0][-1], op.SERVICE)
            self.assertFalse(any("down" in x for x in d.calls))

    def test_source_does_not_have_automated_deploy_surface(self):
        make = (ROOT / "Makefile").read_text()
        for target in ("identity-prod-mongo-start-plan",
                       "identity-prod-mongo-start-inspect"):
            p = subprocess.run(["make", "--no-print-directory", "-n", target],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("host/identity-production-mongo-start.py", p.stdout)
        self.assertNotIn("identity-prod-mongo-start:\n", make)


if __name__ == "__main__":
    unittest.main()
