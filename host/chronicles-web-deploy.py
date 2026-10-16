#!/usr/bin/python3 -I
"""Root-only, Chronicles-web-only Compose deployer for the EXISTING OCI A1.

The installed program is root-owned, its Compose policy is root-owned, and
its only permitted mutation is replacing the dedicated Chronicles web
container at 127.0.0.1:18082. Never accept a script path or Docker arguments.
OCI Run Command must be granted sudo for THIS wrapper only, not Docker.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.error import HTTPError, URLError

# The installed import is a root-owned copy, not a user-writable Git checkout.
sys.path.insert(0, "/usr/local/lib/shadowops")
from shared_a1_host_guard import SharedHostError, verify_shared_a1_containers

COMPOSE = Path("/etc/shadowops/chronicles-web-staging/compose.yaml")
STATE = Path("/var/lib/shadowops/chronicles-web-staging")
IMAGE = "ghcr.io/evilsysadmin/chronicles-web@"
PROJECT = "shadowops-chronicles-web-staging"
SERVICE = "chronicles-web"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MARKER = "CHRONICLES_WEB_OCI_STAGING_SMOKE_OK"
ORIGIN = "http://127.0.0.1:18082/"
MAX_BYTES = 200000


class ReleaseError(ValueError):
    pass


def validate_request(operation: str, digest: str) -> str:
    if operation != "deploy" or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ReleaseError("Only deploy with a lowercase immutable SHA-256 digest is permitted")
    return digest


def check_root_file(path: Path, *, executable: bool = False) -> None:
    """Refuse untrusted Compose or policy installed from a writable checkout."""
    if path.is_symlink():
        raise ReleaseError("Installed release policy must not be a symlink")
    try:
        metadata = path.stat()
        parent = path.parent.stat()
    except OSError as exc:
        raise ReleaseError("Installed release policy is missing") from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
        or metadata.st_mode & 0o022 or parent.st_uid != 0 or parent.st_mode & 0o022):
        raise ReleaseError("Installed release policy must be root-owned and not writable")
    if executable and not metadata.st_mode & stat.S_IXUSR:
        raise ReleaseError("Installed executable is not executable by root")


def assert_compose(config: dict, digest: str) -> None:
    if not isinstance(config, dict) or config.get("name") != PROJECT:
        raise ReleaseError("Unexpected Compose project identity")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != {SERVICE}:
        raise ReleaseError("Compose may manage Chronicles web only")
    web = services[SERVICE]
    if (web.get("image") != IMAGE + digest or web.get("platform") != "linux/arm64"
        or web.get("user") != "101:101" or web.get("read_only") is not True
        or web.get("init") is not True or web.get("cap_drop") != ["ALL"]
        or "no-new-privileges:true" not in web.get("security_opt", [])):
        raise ReleaseError("Unsigned, unapproved or unsafe web container config")
    ports = web.get("ports")
    if (not isinstance(ports, list) or len(ports) != 1
        or ports[0].get("host_ip") != "127.0.0.1"
        or str(ports[0].get("published")) != "18082"
        or ports[0].get("target") != 8080
        or ports[0].get("protocol", "tcp") != "tcp"):
        raise ReleaseError("Chronicles web must bind loopback port 18082 only")
    if (web.get("privileged") or web.get("volumes") or web.get("devices")
        or web.get("network_mode") == "host" or web.get("pid") == "host"
        or web.get("env_file") or web.get("environment") or config.get("secrets")):
        raise ReleaseError("Unexpected container privileges, mounts or environment")


def fixed_compose_args(*parts: str) -> list[str]:
    return ["docker", "compose", "--project-directory", str(COMPOSE.parent),
            "-f", str(COMPOSE), *parts]


def checked_run(
    runner: Callable, args: list[str], env: Mapping[str, str], *, output: bool = False
) -> str:
    try:
        result = runner(args, env=dict(env), cwd=str(COMPOSE.parent),
                        text=True, capture_output=True, timeout=220)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("Chronicles-only Docker action could not complete") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        # Avoid echoing Docker daemon output: it might include private metadata.
        raise ReleaseError("Chronicles-only Docker action failed")
    if output:
        if len(result.stdout) > 500000:
            raise ReleaseError("Docker Compose config exceeded bounded output")
        return result.stdout
    return ""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_local_origin(opener=None) -> None:
    """Loopback GET only; no proxies or HTTP redirects."""
    client = opener or build_opener(ProxyHandler({}), NoRedirect())
    request = Request(ORIGIN, method="GET")
    try:
        with client.open(request, timeout=8) as response:
            if response.geturl() != ORIGIN or response.status != 200:
                raise ReleaseError("Unexpected Chronicles web origin response")
            page = response.read(MAX_BYTES + 1)
    except (OSError, HTTPError, URLError, UnicodeError) as exc:
        raise ReleaseError("Chronicles web origin smoke failed") from exc
    if len(page) > MAX_BYTES:
        raise ReleaseError("Chronicles web origin exceeded the smoke limit")
    if b"CHRONICLES OF MATTHIAS" not in page or "todavía no es el juego".encode() not in page:
        raise ReleaseError("Chronicles web origin returned unexpected content")


def persist_receipt(state: Path, digest: str) -> None:
    payload = {
        "project": PROJECT,
        "service": SERVICE,
        "digest": digest,
        "smoke": True,
        "deployedAt": datetime.now(timezone.utc).isoformat(),
    }
    handle = None
    try:
        fd, name = tempfile.mkstemp(dir=state, prefix=".verified-", suffix=".json")
        handle = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(handle, state / "last-verified-web.json")
        handle = None
        directory_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ReleaseError("Unable to commit verified web receipt") from exc
    finally:
        if handle is not None:
            handle.unlink(missing_ok=True)


def deploy(
    digest: str, *, runner: Callable = subprocess.run,
    guard: Callable = verify_shared_a1_containers,
    smoke: Callable = verify_local_origin,
    env: Mapping[str, str] | None = None,
    state: Path = STATE,
    policy: Path = COMPOSE,
    require_root: bool = True,
) -> str:
    validate_request("deploy", digest)
    if require_root and os.geteuid() != 0:
        raise ReleaseError("Chronicles web deployer requires root")
    if policy != COMPOSE:
        raise ReleaseError("Only the installed fixed Compose policy is permitted")
    check_root_file(policy)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.is_symlink():
        raise ReleaseError("Unsafe Chronicles web receipt directory")
    meta = state.stat()
    if (require_root and meta.st_uid != 0) or meta.st_mode & 0o077:
        raise ReleaseError("Chronicles web receipt directory must remain private")
    values = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
              "CHRONICLES_WEB_IMAGE_DIGEST": digest}
    if env:
        # Inputs are intentionally not allowed to influence the Docker environment.
        _ = env
    with (state / "deploy.lock").open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            guard(runner)
        except SharedHostError as exc:
            raise ReleaseError("Shared A1 ownership guard rejected host state") from exc
        config_text = checked_run(runner, fixed_compose_args("config", "--format", "json"),
                                  values, output=True)
        try:
            config = json.loads(config_text)
        except ValueError as exc:
            raise ReleaseError("Compose configuration returned invalid JSON") from exc
        assert_compose(config, digest)
        # Pull may cache a new image but cannot modify an existing workload.
        checked_run(runner, fixed_compose_args("pull", SERVICE), values)
        try:
            guard(runner)
        except SharedHostError as exc:
            raise ReleaseError("Shared A1 changed during admission") from exc
        # A previously verified release becomes unverified BEFORE any mutation.
        (state / "last-verified-web.json").unlink(missing_ok=True)
        checked_run(runner, fixed_compose_args(
            "up", "--detach", "--wait", "--wait-timeout", "120",
            "--no-deps", "--no-build", "--pull", "never", SERVICE
        ), values)
        smoke()
        persist_receipt(state, digest)
    return MARKER + " digest=" + digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("deploy",))
    parser.add_argument("digest")
    args = parser.parse_args()
    try:
        print(deploy(validate_request(args.operation, args.digest)))
    except (ReleaseError, BlockingIOError, OSError) as exc:
        # No Docker stdout/stderr, only bounded diagnostic category.
        print("CHRONICLES_WEB_OCI_DEPLOY_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
