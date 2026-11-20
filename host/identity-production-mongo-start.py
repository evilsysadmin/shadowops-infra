#!/usr/bin/env python3
"""Manual, scoped first start for isolated production Mongo on OCI A1.

Plan: no Docker / secrets. Inspect: read-only exact preflight. Start: only
the pre-pulled production Mongo container, never Identity, staging or tunnel.
The replica set, first admin and off-host backup remain separate approvals.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

# Load an exact trusted sibling; this module does not consult CWD/PYTHONPATH.
SCRIPT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_host", SCRIPT.parents[1] / "scripts/identity_production_mongo_host.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_HOST_REFUSED")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

LOCK = Path("/run/lock/shadowops-identity-production-mongo-start.lock")
ACK = "START_EMPTY_ISOLATED_PRODUCTION_MONGO_ONLY"
COMPOSE = host.COMPOSE
PROFILE = "production-mongo"
SERVICE = host.SERVICE
PROJECT = host.PROJECT
CONTAINER = PROJECT + "-" + SERVICE + "-1"
CONTAINER_LABELS = {
    "com.docker.compose.project": PROJECT,
    "com.docker.compose.service": SERVICE,
}
VOLUME = host.VOLUME
NETWORK = host.NETWORK
SENSITIVE_WORDS = ("mongo_admin_uri", "password", "private")


class Refused(ValueError):
    pass


def docker(*args: str, timeout: int = 30, limit: int = 65536,
           runner=subprocess.run) -> str:
    try:
        result = runner(["docker", *args], capture_output=True,
                        text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("local Docker command unavailable") from None
    if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > limit:
        # Docker errors can disclose paths and mount details: never echo them.
        raise Refused("local Docker operation refused")
    return result.stdout.strip()


def compose(*args: str, runner=subprocess.run) -> str:
    return docker("compose", "-f", str(COMPOSE), "--profile", PROFILE,
                  *args, runner=runner, timeout=90)


def ensure_empty(runner=subprocess.run) -> None:
    # Force a successful Docker daemon round-trip before interpreting empty lists.
    docker("info", "--format", "{{.ServerVersion}}", runner=runner)
    for args in (
        ("ps", "-a", "--filter", "label=com.docker.compose.project=" + PROJECT,
         "--format", "{{.ID}}"),
        ("volume", "ls", "--filter", "name=^" + VOLUME + "$", "--format", "{{.Name}}"),
        ("network", "ls", "--filter", "name=^" + NETWORK + "$", "--format", "{{.Name}}"),
    ):
        if docker(*args, runner=runner):
            raise Refused("Mongo project, volume or network already exists")


def image_admission(*, runner=subprocess.run) -> None:
    data = docker("image", "inspect", "--format", "{{json .}}", host.IMAGE,
                  runner=runner)
    try:
        obj = json.loads(data)
        if (not isinstance(obj, dict) or obj.get("Architecture") != "arm64" or
                obj.get("Os") != "linux" or
                not re.fullmatch(r"sha256:[0-9a-f]{64}", obj.get("Id", "")) or
                host.IMAGE not in obj.get("RepoDigests", [])):
            raise Refused("expected pinned ARM64 image not available locally")
    except (ValueError, TypeError, AttributeError):
        raise Refused("invalid local Mongo image metadata") from None


def rendered_compose_admission(*, runner=subprocess.run) -> None:
    raw = compose("config", "--format", "json", runner=runner)
    try:
        config = json.loads(raw)
        service = config["services"][SERVICE]
        if (config["name"] != PROJECT or
                set(config["services"]) != {SERVICE} or
                service["image"] != host.IMAGE or
                service.get("user") != "999:999" or
                service.get("read_only") is not True or
                service.get("privileged", False) is not False or
                service.get("restart") != "no" or
                service.get("ports") or
                set(service["networks"]) != {"identity-mongo-egress"} or
                config["volumes"]["identity-production-data"]["name"] != VOLUME or
                config["networks"]["identity-mongo-egress"]["name"] != NETWORK or
                config["networks"]["identity-mongo-egress"].get("internal") is not True):
            raise Refused("rendered Mongo security contract not admitted")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Refused("invalid rendered Mongo Compose") from None


def preflight(*, runner=subprocess.run) -> None:
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        raise Refused("CI may not access operator Mongo")
    host.validate_compose(COMPOSE.read_text(encoding="utf-8"))
    host.inspect_private_files()
    image_admission(runner=runner)
    ensure_empty(runner=runner)
    rendered_compose_admission(runner=runner)


def manual_approval() -> None:
    if (os.geteuid() != 0 or os.environ.get("CI") or
            os.environ.get("GITHUB_ACTIONS") or not sys.stdin.isatty()):
        raise Refused("root interactive terminal required")
    if input("Confirm exact first Mongo start: ").strip() != ACK:
        raise Refused("operator did not authorize first Mongo start")


@contextmanager
def single_operator():
    # No attacker-supplied symlink or inherited file with permissive mode.
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                stat.S_IMODE(meta.st_mode) != 0o600):
            raise Refused("Mongo operator lock metadata unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("another Mongo operator is active") from None
        yield
    finally:
        os.close(fd)


def poststart(*, runner=subprocess.run) -> None:
    rows = docker("ps", "-a", "--filter",
                  "label=com.docker.compose.project=" + PROJECT,
                  "--format", "{{.ID}}", runner=runner).splitlines()
    if len(rows) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", rows[0]):
        raise Refused("unexpected post-start Mongo container inventory")
    raw = docker("inspect", "--format", "{{json .}}", rows[0], runner=runner)
    try:
        data = json.loads(raw)
        config = data["Config"]
        runtime = data["HostConfig"]
        mounts = {m["Destination"]: m for m in data["Mounts"]}
        labels = config["Labels"]
        if (data["Name"] != "/" + CONTAINER or
                any(labels.get(k) != v for k, v in CONTAINER_LABELS.items()) or
                config["Image"] != host.IMAGE or config["User"] != "999:999" or
                data["State"]["Running"] is not True or
                runtime["ReadonlyRootfs"] is not True or runtime["Privileged"] is not False or
                runtime.get("PortBindings") or
                set(data["NetworkSettings"]["Networks"]) != {NETWORK} or
                mounts["/data/db"]["Name"] != VOLUME or
                mounts["/data/db"]["Type"] != "volume" or
                mounts["/run/mongo"]["Source"] != str(host.SECRET_DIR) or
                mounts["/run/mongo"]["RW"] is not False):
            raise Refused("unexpected production Mongo container security state")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Refused("invalid post-start Mongo container inspect") from None
    return rows[0]  # exact inspected container ID, never an unpinned name


def start(*, runner=subprocess.run) -> None:
    manual_approval()
    with single_operator():
        preflight(runner=runner)
        started = False
        try:
            # No build/pull/deps; only exact standalone Mongo service.
            started = True  # even a failed up may create a stopped container
            compose("up", "--detach", "--no-build", "--no-deps", "--pull", "never",
                    SERVICE, runner=runner)
            poststart(runner=runner)
        except Exception:
            if started:
                try:
                    compose("stop", "--timeout", "20", SERVICE, runner=runner)
                except Refused:
                    raise Refused("Mongo start failed; scoped rollback also refused") from None
            raise Refused("Mongo first start refused; stopped scoped service") from None


def main(args: list[str]) -> int:
    if args == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_START_PLAN"
              " exact_image=arm64-pinned first_start=manual"
              " existing_project=deny existing_volume=deny"
              " backup=not-proven replica=not-initialized")
        return 0
    if args not in (["inspect"], ["start"]):
        print("Usage: identity-production-mongo-start.py plan|inspect|start", file=sys.stderr)
        return 2
    try:
        if args == ["inspect"]:
            preflight()
            print("IDENTITY_PRODUCTION_MONGO_START_INSPECT_OK"
                  " local_image=pinned tls_material=present"
                  " mongo=not-started replica=not-initialized")
        else:
            start()
            print("IDENTITY_PRODUCTION_MONGO_START_OK"
                  " container=running replica=not-initialized"
                  " admin=not-created backups=not-proven")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_START_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
