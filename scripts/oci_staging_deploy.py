#!/usr/bin/env python3
"""Fail-closed OCI A1 Chronicles staging launcher.

This runs ONLY on a provisioned dedicated staging host. The default mode
performs read-only GitHub/GHCR admission, host preflight and Compose checks.
--deploy-staging explicitly opts in to changing the Chronicles staging
container and requires a synthetic authenticated-read smoke afterwards.
No production deployment, Chess Studio orchestration or secret logging.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import platform
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Mapping

from staging_host_preflight import PreflightError, verify_staging_environment
from staging_read_smoke import SmokeError, read_private_token, verify_staging_reads

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[a-f0-9]{40}$")
IMAGE = "ghcr.io/evilsysadmin/chronicles-api@"
COMPOSE = ("docker", "compose", "-f", "compose.yaml", "-f", "compose.staging.yaml")


class DeployError(Exception):
    """Deployment admission failed without disclosing credentials."""


def _command(runner: Callable, args: list[str], env: Mapping[str, str], description: str):
    try:
        result = runner(
            args, cwd=ROOT, env=dict(env), text=True, capture_output=True, timeout=240
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeployError(description + " could not run") from exc
    if result.returncode != 0:
        # Never print stdout/stderr: OCI tooling could reveal secret material.
        raise DeployError(description + " failed")
    return result.stdout


def _assert_compose(config: dict, digest: str) -> None:
    if not isinstance(config, dict) or config.get("name") != "shadowops-chronicles-staging":
        raise DeployError("staging project identity mismatch")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != {"chronicles-api"}:
        raise DeployError("staging may manage the Chronicles API service only")
    api = services["chronicles-api"]
    if api.get("image") != IMAGE + digest or api.get("platform") != "linux/arm64":
        raise DeployError("staging image digest or OCI A1 platform mismatch")
    if api.get("read_only") is not True or api.get("init") is not True:
        raise DeployError("staging runtime isolation missing")
    if api.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in api.get("security_opt", []):
        raise DeployError("staging container security policy mismatch")
    if api.get("healthcheck", {}).get("test") != ["CMD", "/app/chronicles-api", "readycheck"]:
        raise DeployError("dependency readiness healthcheck is required")
    ports = api.get("ports")
    if (
        not isinstance(ports, list) or len(ports) != 1
        or ports[0].get("host_ip") != "127.0.0.1"
        or str(ports[0].get("published")) != "18081"
        or ports[0].get("target") != 8080
    ):
        raise DeployError("staging API must bind loopback port 18081 only")
    environment = api.get("environment", {})
    expected = {
        "CHRONICLES_ENVIRONMENT": "staging",
        "CHRONICLES_ENABLE_READ_API": "true",
        "CHRONICLES_MONGODB_URI_FILE": "/run/secrets/chronicles_mongodb_uri",
        "CHRONICLES_JWT_SECRET_FILE": "/run/secrets/chronicles_staging_jwt",
    }
    if not isinstance(environment, dict) or any(
        environment.get(key) != value for key, value in expected.items()
    ) or "CHRONICLES_MONGODB_URI" in environment or "CHRONICLES_JWT_SECRET" in environment:
        raise DeployError("staging read API secrets or runtime policy mismatch")
    sources = {item.get("source") for item in api.get("secrets", [])}
    if sources != {"chronicles_mongodb_uri", "chronicles_staging_jwt"}:
        raise DeployError("staging secret mounts do not match policy")


@contextmanager
def _exclusive_lock(directory: Path):
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise DeployError("unsafe staging lock directory")
        directory.chmod(0o700)
        lock_path = directory / "oci-deploy.lock"
        if lock_path.is_symlink():
            raise DeployError("unsafe staging lock file")
        with lock_path.open("a", encoding="utf-8") as handle:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DeployError("another Chronicles staging deploy is in progress") from exc
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError as exc:
        raise DeployError("cannot acquire private staging deploy lock") from exc


def run_staging(
    *, sha: str, run_id: int, env: Mapping[str, str],
    deploy: bool = False, runner: Callable = subprocess.run,
    architecture: str | None = None, host_preflight: Callable = verify_staging_environment,
    smoke: Callable = verify_staging_reads, token_reader: Callable = read_private_token,
    lock_dir: Path | None = None,
) -> str:
    if not SHA.fullmatch(sha) or not isinstance(run_id, int) or run_id <= 0:
        raise DeployError("source SHA or publishing workflow run ID is invalid")
    if not env.get("GH_TOKEN"):
        raise DeployError("read-only GitHub admission token is missing")
    if (architecture or platform.machine()).lower() not in {"aarch64", "arm64"}:
        raise DeployError("Chronicles staging must run on an OCI Ampere A1 ARM64 host")
    try:
        digest = host_preflight(env)
    except PreflightError as exc:
        raise DeployError("staging host preflight: " + str(exc)) from exc

    home = Path(env.get("HOME") or str(Path.home()))
    state = lock_dir or home / ".local" / "state" / "chronicles-staging"
    with _exclusive_lock(state):
        # Independently verify source workflow, main protection, all CI jobs
        # and signed GHCR manifest. No operator-provided check lists allowed.
        _command(runner, [
            "node", "scripts/check-staging-candidate.mjs",
            "--sha", sha, "--digest", digest, "--run-id", str(run_id),
        ], env, "signed staging image admission")

        config_json = _command(runner, [
            *COMPOSE, "config", "--format", "json"
        ], env, "staging Compose validation")
        if len(config_json) > 1_000_000:
            raise DeployError("staging Compose response too large")
        try:
            config = json.loads(config_json)
        except (ValueError, TypeError) as exc:
            raise DeployError("staging Compose configuration is invalid JSON") from exc
        _assert_compose(config, digest)

        if not deploy:
            return "CHRONICLES_OCI_STAGING_PREFLIGHT_OK"

        expected = {
            "owner": env.get("CHRONICLES_SMOKE_OWNER_TOKEN_FILE"),
            "other": env.get("CHRONICLES_SMOKE_OTHER_TOKEN_FILE"),
            "run": env.get("CHRONICLES_SMOKE_RUN_ID"),
            "map": env.get("CHRONICLES_SMOKE_EXPECTED_MAP"),
        }
        if not all(expected.values()):
            raise DeployError("synthetic smoke fixtures are required before deploying")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", expected["run"]):
            raise DeployError("invalid synthetic fixture run ID")
        try:
            owner = token_reader(expected["owner"])
            other = token_reader(expected["other"])
        except SmokeError as exc:
            raise DeployError("synthetic smoke JWT files are invalid") from exc
        if owner == other:
            raise DeployError("synthetic smoke users must be different")

        _command(runner, [*COMPOSE, "pull", "chronicles-api"], env, "immutable staging image pull")
        _command(runner, [
            *COMPOSE, "up", "--detach", "--wait", "--wait-timeout", "180",
            "--no-deps", "--no-build", "--pull", "never", "chronicles-api",
        ], env, "isolated Chronicles staging deployment")
        try:
            smoke("http://127.0.0.1:18081", owner, other, expected["run"], expected["map"])
        except (SmokeError, OSError, TimeoutError) as exc:
            raise DeployError("synthetic staging HTTP smoke failed; investigate or roll back") from exc
        return "CHRONICLES_OCI_STAGING_VERIFIED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="exact 40-character source commit SHA")
    parser.add_argument("--run-id", required=True, type=int, help="exact GitHub publication run")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-only", action="store_true", help="default: never deploy")
    mode.add_argument("--deploy-staging", action="store_true", help="explicit OCI staging deploy and synthetic smoke")
    args = parser.parse_args(argv)
    try:
        result = run_staging(
            sha=args.sha, run_id=args.run_id, env=os.environ,
            deploy=args.deploy_staging,
        )
    except DeployError as exc:
        print("CHRONICLES_OCI_STAGING_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
