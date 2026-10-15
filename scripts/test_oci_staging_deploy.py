"""Offline tests for the OCI staging deploy executor; Docker/OCI never run."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from oci_staging_deploy import DeployError, run_staging

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
ENV = {
    "GH_TOKEN": "fake-read-only-token",
    "CHRONICLES_IMAGE_DIGEST": DIGEST,
    "CHRONICLES_MONGODB_DATABASE": "chronicles_staging",
    "CHRONICLES_SMOKE_OWNER_TOKEN_FILE": "/private/owner.jwt",
    "CHRONICLES_SMOKE_OTHER_TOKEN_FILE": "/private/other.jwt",
    "CHRONICLES_SMOKE_RUN_ID": "fixture-run",
    "CHRONICLES_SMOKE_EXPECTED_MAP": "crypt-eight-squares",
}
COMPOSE = {
    "name": "shadowops-chronicles-staging",
    "services": {
        "chronicles-api": {
            "image": "ghcr.io/evilsysadmin/chronicles-api@" + DIGEST,
            "platform": "linux/arm64",
            "read_only": True,
            "init": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "healthcheck": {"test": ["CMD", "/app/chronicles-api", "readycheck"]},
            "ports": [{
                "host_ip": "127.0.0.1", "published": "18081", "target": 8080
            }],
            "environment": {
                "CHRONICLES_ENVIRONMENT": "staging",
                "CHRONICLES_ENABLE_READ_API": "true",
                "CHRONICLES_MONGODB_URI_FILE": "/run/secrets/chronicles_mongodb_uri",
                "CHRONICLES_JWT_SECRET_FILE": "/run/secrets/chronicles_staging_jwt",
                "CHRONICLES_MONGODB_DATABASE": "chronicles_staging",
            },
            "secrets": [
                {"source": "chronicles_mongodb_uri"},
                {"source": "chronicles_staging_jwt"}
            ]
        }
    }
}


def fake_host_preflight(env):
    assert env["CHRONICLES_MONGODB_DATABASE"] == "chronicles_staging"
    return DIGEST


class Runner:
    def __init__(self, config=None, failed=None):
        self.calls = []
        self.config = config if config is not None else COMPOSE
        self.failed = failed

    def __call__(self, args, **_kwargs):
        self.calls.append(tuple(args))
        command = args[0] if args else ""
        if self.failed == command:
            return subprocess.CompletedProcess(args, 1, "", "private secret must not leak")
        value = (
            json.dumps(self.config)
            if command == "docker" and "config" in args
            else "STAGING_CANDIDATE_ACCREDITED"
            if command == "node" else ""
        )
        return subprocess.CompletedProcess(args, 0, value, "")


class A1DeployContractTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.lock_dir = Path(self.folder.name) / "lock"

    def run_with(self, runner, **kwargs):
        return run_staging(
            sha=SHA, run_id=38812775390, env=ENV,
            architecture="aarch64", host_preflight=fake_host_preflight,
            runner=runner, lock_dir=self.lock_dir, **kwargs
        )

    def test_read_only_mode_never_invokes_mutating_docker_actions(self):
        runner = Runner()
        result = self.run_with(runner)
        self.assertEqual(result, "CHRONICLES_OCI_STAGING_PREFLIGHT_OK")
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[0][0], "node")
        self.assertIn("check-staging-candidate.mjs", runner.calls[0][1])
        self.assertEqual(runner.calls[1][-3:], ("config", "--format", "json"))
        self.assertEqual(self.lock_dir.stat().st_mode & 0o777, 0o700)

    def test_explicit_apply_pulls_one_service_and_requires_synthetic_smoke(self):
        runner = Runner()
        observed = []
        result = self.run_with(
            runner, deploy=True,
            token_reader=lambda path: "verified-alice" if "owner" in path else "verified-bob",
            smoke=lambda *args: observed.append(args),
        )
        self.assertEqual(result, "CHRONICLES_OCI_STAGING_VERIFIED")
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], "http://127.0.0.1:18081")
        self.assertEqual(observed[0][3], "fixture-run")
        self.assertEqual(len(runner.calls), 4)
        self.assertEqual(runner.calls[2][-2:], ("pull", "chronicles-api"))
        self.assertIn("--wait", runner.calls[3])
        self.assertEqual(runner.calls[3][-1], "chronicles-api")
        self.assertNotIn("chess-studio", " ".join(" ".join(x) for x in runner.calls))

    def test_no_deploy_on_invalid_source_host_or_missing_account_tokens(self):
        for overrides in [
            {"sha": "main"},
            {"run_id": 0},
            {"architecture": "x86_64"},
            {"env": {**ENV, "GH_TOKEN": ""}},
            {"env": {**ENV, "CHRONICLES_SMOKE_OTHER_TOKEN_FILE": ""}},
        ]:
            with self.subTest(overrides=overrides):
                runner = Runner()
                values = {
                    "sha": SHA, "run_id": 38812775390, "env": ENV,
                    "architecture": "aarch64", "host_preflight": fake_host_preflight,
                    "runner": runner, "lock_dir": self.lock_dir,
                    "deploy": True,
                    "token_reader": lambda path: "token-a" if "owner" in path else "token-b",
                }
                values.update(overrides)
                with self.assertRaises(DeployError):
                    run_staging(**values)
                self.assertFalse(any("pull" in call or "up" in call for call in runner.calls))

    def test_rejects_wrong_compose_project_or_runtime_permissions_before_mutation(self):
        def bad(**changes):
            config = json.loads(json.dumps(COMPOSE))
            config["services"]["chronicles-api"].update(changes)
            return config
        for config in [
            {**COMPOSE, "name": "chess-studio-staging"},
            {**COMPOSE, "services": {**COMPOSE["services"], "chess-api": {}}},
            bad(platform="linux/amd64"),
            bad(image="ghcr.io/evilsysadmin/chronicles-api:latest"),
            bad(read_only=False),
            bad(cap_drop=[]),
            bad(ports=[{"host_ip": "0.0.0.0", "published": "18081", "target": 8080}]),
            bad(secrets=[]),
            bad(healthcheck={"test": ["CMD", "true"]}),
            bad(environment={"CHRONICLES_ENVIRONMENT": "production"}),
        ]:
            with self.subTest(config=config):
                runner = Runner(config=config)
                with self.assertRaises(DeployError):
                    self.run_with(runner, deploy=True, token_reader=lambda path: path)
                self.assertEqual(len(runner.calls), 2)

    def test_registry_or_signed_admission_failure_blocks_deploy_without_log_leak(self):
        for command in ("node", "docker"):
            runner = Runner(failed=command)
            with self.assertRaises(DeployError) as caught:
                self.run_with(runner, deploy=True, token_reader=lambda path: path)
            self.assertNotIn("private secret", str(caught.exception))
            self.assertFalse(any("pull" in call or "up" in call for call in runner.calls))

    def test_operator_must_supply_distinct_synthetic_tokens(self):
        runner = Runner()
        with self.assertRaisesRegex(DeployError, "different"):
            self.run_with(runner, deploy=True, token_reader=lambda path: "same-token")
        self.assertEqual(len(runner.calls), 2)


if __name__ == "__main__":
    unittest.main()
