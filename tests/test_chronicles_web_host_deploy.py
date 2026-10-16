"""Offline, least-privilege contracts for the installed Chronicles web deployer."""
from __future__ import annotations
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("chronicles_web_host_deploy",
    ROOT / "host" / "chronicles-web-deploy.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
from shared_a1_host_guard import SharedHostError

DIGEST = "sha256:" + "a" * 64


def policy(digest=DIGEST):
    return {
        "name": "shadowops-chronicles-web-staging",
        "services": {"chronicles-web": {
            "image": "ghcr.io/evilsysadmin/chronicles-web@" + digest,
            "platform": "linux/arm64",
            "user": "101:101",
            "read_only": True,
            "init": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "ports": [{"host_ip": "127.0.0.1", "published": "18082",
                        "target": 8080, "protocol": "tcp"}],
        }},
    }


class FakeRunner:
    def __init__(self, *, config=None, fail_at=None):
        self.commands = []
        self.config = config or policy()
        self.fail_at = fail_at

    def __call__(self, args, **kwargs):
        self.commands.append((args, kwargs))
        if self.fail_at and self.fail_at in args:
            return subprocess.CompletedProcess(args, 1, "private data", "other secrets")
        if "config" in args:
            result = json.dumps(self.config)
        else:
            result = "unknown-private-command-output"
        return subprocess.CompletedProcess(args, 0, result, "")


class WebHostDeployerTests(unittest.TestCase):
    def test_accepted_invocation_must_have_exactly_one_digest(self):
        self.assertEqual(web.validate_request("deploy", DIGEST), DIGEST)
        for operation, digest in (
            ("status", DIGEST), ("rollback", DIGEST), ("deploy", "latest"),
            ("deploy", "sha256:" + "A" * 64),
            ("deploy", DIGEST + " --privileged"),
            ("deploy", DIGEST + "\n/usr/bin/bash"),
            ("deploy", "sha256:" + "a" * 63),
        ):
            with self.subTest(operation=operation, digest=digest):
                with self.assertRaises(web.ReleaseError):
                    web.validate_request(operation, digest)

    def test_refuses_untrusted_project_writable_policy_or_mounts(self):
        web.assert_compose(policy(), DIGEST)
        for change in (
            {"image": "ghcr.io/evilsysadmin/chess-studio@" + DIGEST},
            {"volumes": ["/:/host:rw"]},
            {"privileged": True},
            {"environment": {"MONGO_URL": "x"}},
            {"network_mode": "host"},
            {"ports": [{"host_ip": "0.0.0.0", "published": "18082",
                        "target": 8080}]},
            {"cap_drop": []},
        ):
            obj = policy()
            obj["services"]["chronicles-web"].update(change)
            with self.subTest(change=change), self.assertRaises(web.ReleaseError):
                web.assert_compose(obj, DIGEST)
        obj = policy()
        obj["services"]["chess-studio"] = {}
        with self.assertRaises(web.ReleaseError):
            web.assert_compose(obj, DIGEST)

    def test_success_mutates_only_the_exact_web_service_then_smokes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            runner = FakeRunner()
            sequence = []
            def guard(_):
                sequence.append("guard")
            def smoke():
                sequence.append("smoke")
            with patch.object(web, "check_root_file"):
                result = web.deploy(DIGEST, runner=runner, guard=guard, smoke=smoke,
                                    state=state, require_root=False)
            self.assertTrue(result.startswith(web.MARKER))
            self.assertEqual(sequence, ["guard", "guard", "smoke"])
            self.assertEqual(len(runner.commands), 3)
            for args, kwargs in runner.commands:
                self.assertEqual(args[:6], [
                    "docker", "compose", "--project-directory", str(web.COMPOSE.parent),
                    "-f", str(web.COMPOSE)])
                self.assertEqual(kwargs["env"]["CHRONICLES_WEB_IMAGE_DIGEST"], DIGEST)
                self.assertEqual(set(kwargs["env"]), {"PATH", "CHRONICLES_WEB_IMAGE_DIGEST"})
                self.assertNotIn("chess-studio", " ".join(args))
            self.assertEqual(runner.commands[1][0][-2:], ["pull", "chronicles-web"])
            up = runner.commands[2][0]
            self.assertEqual(up[-1], "chronicles-web")
            self.assertIn("--no-deps", up)
            self.assertIn("--no-build", up)
            receipt = json.loads((state / "last-verified-web.json").read_text())
            self.assertEqual(receipt["digest"], DIGEST)
            self.assertTrue(receipt["smoke"])
            self.assertEqual((state / "last-verified-web.json").stat().st_mode & 0o777, 0o600)

    def test_guard_or_compose_failure_prevents_docker_mutation(self):
        for mode in ("foreign", "bad-config", "pull-failure", "late-foreign"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                runner = FakeRunner(config=policy(), fail_at="pull" if mode == "pull-failure" else None)
                if mode == "bad-config":
                    runner.config["services"]["chronicles-web"]["ports"][0]["host_ip"] = "0.0.0.0"
                calls = []
                def guard(_):
                    calls.append(1)
                    if mode == "foreign" or (mode == "late-foreign" and len(calls) == 2):
                        raise SharedHostError("do not expose secret or foreign metadata")
                with patch.object(web, "check_root_file"):
                    with self.assertRaises(web.ReleaseError):
                        web.deploy(DIGEST,runner=runner,guard=guard,smoke=lambda:None,
                                   state=pathlib.Path(directory),require_root=False)
                self.assertFalse(any("up" in args for args,_ in runner.commands))
                self.assertFalse((pathlib.Path(directory) / "last-verified-web.json").exists())

    def test_failed_http_smoke_invalidates_prior_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            (state / "last-verified-web.json").write_text("old-but-once-good")
            runner = FakeRunner()
            with patch.object(web, "check_root_file"):
                with self.assertRaises(web.ReleaseError):
                    web.deploy(DIGEST,runner=runner,guard=lambda _:None,
                               smoke=lambda: (_ for _ in ()).throw(web.ReleaseError("bad")),
                               state=state,require_root=False)
            self.assertFalse((state / "last-verified-web.json").exists())
            self.assertIn("up", runner.commands[-1][0])

    def test_host_install_is_outside_ci_and_user_privileges(self):
        installer = (ROOT / "host/install-chronicles-web.sh").read_text()
        sudoers = (ROOT / "host/chronicles-web.sudoers").read_text()
        workflow = (ROOT / ".github/workflows/chronicles-web-runtime.yml").read_text()
        self.assertIn("SHADOWOPS_CHRONICLES_WEB_HOST_WRAPPER_INSTALLED", installer)
        self.assertIn("root-required", installer)
        self.assertIn("status --porcelain", installer)
        self.assertIn("visudo -cf", installer)
        self.assertIn("ocarun ALL=(root) NOPASSWD: SHADOWOPS_CHRONICLES_WEB", sudoers)
        self.assertNotIn("NOPASSWD:ALL", sudoers)
        self.assertNotIn("usermod -aG docker ocarun", installer)
        self.assertIn("test_chronicles_web_host_deploy.py", workflow)
        self.assertNotIn("docker compose up", workflow)


if __name__ == "__main__":
    unittest.main()
