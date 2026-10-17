#!/usr/bin/python3 -I
"""Root-only, Chronicles-API-only Compose deployer for the EXISTING OCI A1.

Accepts exactly: deploy sha256:<64 hex> ocid1.vault.<...> [staging|production]
(without an environment it is staging, as before).

Runtime secrets are never passed in: the wrapper reads ONE Vault bundle,
`chronicles-staging-runtime-env`, with the A1's Instance Principal through a
root-owned OCI SDK venv, writes two root-only env files and then manages only
the `shadowops-chronicles-staging` project (API on 127.0.0.1:18081 + its own
Cloudflare Tunnel connector). Docker and Vault output are never echoed.
"""
from __future__ import annotations

import argparse
import base64
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
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

sys.path.insert(0, "/usr/local/lib/shadowops")
from shared_a1_host_guard import SharedHostError, verify_shared_a1_containers  # noqa: E402

COMPOSE = Path("/etc/shadowops/chronicles-api-staging/compose.yaml")
RUNTIME = Path("/etc/shadowops/chronicles-api-staging")
API_ENV = RUNTIME / "api.env"
TUNNEL_ENV = RUNTIME / "tunnel.env"
STATE = Path("/var/lib/shadowops/chronicles-api-staging")
OCI_PYTHON = Path("/opt/shadowops/oci-venv/bin/python")
PROJECT = "shadowops-chronicles-staging"
API, TUNNEL = "chronicles-api", "chronicles-tunnel"
API_IMAGE = "ghcr.io/evilsysadmin/chronicles-api@"
TUNNEL_IMAGE = ("cloudflare/cloudflared@sha256:"
                "b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4")
SECRET_NAME = "chronicles-staging-runtime-env"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VAULT_RE = re.compile(r"^ocid1\.vault\.[A-Za-z0-9._-]{10,200}$")
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
BUNDLE_KEYS = frozenset({"MONGO_URL", "JWT_SECRET", "INVITE_CODE", "TUNNEL_TOKEN"})
PUBLIC_ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
# Non-secret runtime contract, versioned here rather than in Vault.
STATIC_API_ENV = (
    ("MONGO_DB_NAME", "chronicles_staging"),
    ("ENVIRONMENT", "staging"),
    ("PORT", "8080"),
    ("CORS_ORIGINS", PUBLIC_ORIGIN),
    ("ALLOW_REGISTRATION", "true"),
    ("ENABLE_EMAIL_RECOVERY", "false"),
    # All public traffic arrives through the tunnel: client IPs come from CF.
    ("TRUST_CLOUDFLARE_CLIENT_IP", "true"),
)
MARKER = "CHRONICLES_API_OCI_STAGING_SMOKE_OK"
LOCAL = "http://127.0.0.1:18081"


class Target:
    """Everything that differs between environments; nothing else may."""

    def __init__(self, name: str, port: int, origin: str, database: str):
        self.name = name
        self.project = "shadowops-chronicles-" + name
        self.runtime = Path("/etc/shadowops/chronicles-api-" + name)
        self.compose = self.runtime / "compose.yaml"
        self.api_env = self.runtime / "api.env"
        self.tunnel_env = self.runtime / "tunnel.env"
        self.state = Path("/var/lib/shadowops/chronicles-api-" + name)
        self.secret = "chronicles-" + name + "-runtime-env"
        self.port = port
        self.local = f"http://127.0.0.1:{port}"
        self.marker = "CHRONICLES_API_OCI_" + name.upper() + "_SMOKE_OK"
        self.static_env = (
            ("MONGO_DB_NAME", database),
            ("ENVIRONMENT", name),
            ("PORT", "8080"),
            ("CORS_ORIGINS", origin),
            ("ALLOW_REGISTRATION", "true"),
            ("ENABLE_EMAIL_RECOVERY", "false"),
            ("TRUST_CLOUDFLARE_CLIENT_IP", "true"),
        )


TARGETS = {
    "staging": Target("staging", 18081, PUBLIC_ORIGIN, "chronicles_staging"),
    "production": Target("production", 18091, "https://chronicles.shadowops.dpdns.org", "chronicles_production"),
}
STAGING = TARGETS["staging"]
assert STAGING.static_env == STATIC_API_ENV and STAGING.compose == COMPOSE

# Fixed program run by the root-owned OCI venv. Inputs arrive as environment,
# the bundle leaves as base64 on stdout (captured, never printed).
VAULT_READER = r"""
import os, oci
signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
client = oci.secrets.SecretsClient(config={}, signer=signer)
bundle = client.get_secret_bundle_by_name(
    secret_name=os.environ["SECRET_NAME"], vault_id=os.environ["VAULT_ID"], stage="CURRENT"
).data
print(bundle.secret_bundle_content.content, end="")
"""


class ReleaseError(ValueError):
    pass


def validate_request(operation: str, digest: str, vault_id: str,
                     environment: str = "staging") -> tuple[str, str]:
    if operation != "deploy" or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ReleaseError("Only deploy with a lowercase immutable SHA-256 digest is permitted")
    if not isinstance(vault_id, str) or not VAULT_RE.fullmatch(vault_id):
        raise ReleaseError("A Vault OCID is required")
    if environment not in TARGETS:
        raise ReleaseError("Environment must be staging or production")
    return digest, vault_id


def check_root_file(path: Path) -> None:
    if path.is_symlink():
        raise ReleaseError("Installed release policy must not be a symlink")
    try:
        metadata, parent = path.stat(), path.parent.stat()
    except OSError as exc:
        raise ReleaseError("Installed release policy is missing") from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or parent.st_uid != 0 or parent.st_mode & 0o022):
        raise ReleaseError("Installed release policy must be root-owned and not writable")


def parse_bundle(text: str) -> dict[str, str]:
    """KEY=VALUE lines; exactly the expected keys; no control characters."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        if not sep or not KEY_RE.fullmatch(key) or key in values:
            raise ReleaseError("Malformed runtime bundle")
        values[key] = value
    if set(values) != BUNDLE_KEYS:
        raise ReleaseError("Runtime bundle keys do not match the contract")
    for value in values.values():
        if not value or len(value) > 4096 or any(ch in value for ch in "'\x00\r\n"):
            raise ReleaseError("Runtime bundle value is empty or unsafe")
    return values


def read_bundle(vault_id: str, runner: Callable, target: Target = STAGING) -> dict[str, str]:
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SECRET_NAME": target.secret, "VAULT_ID": vault_id}
    try:
        result = runner([str(OCI_PYTHON), "-I", "-c", VAULT_READER], env=env,
                        text=True, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("Vault bundle could not be read") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str) or not result.stdout:
        raise ReleaseError("Vault bundle read failed")
    try:
        text = base64.b64decode(result.stdout, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseError("Vault bundle is not valid base64 UTF-8") from exc
    return parse_bundle(text)


def env_lines(rows) -> str:
    # Single quotes: Compose treats the value literally (no ${} interpolation).
    return "".join(f"{key}='{value}'\n" for key, value in rows)


def write_private(path: Path, content: str) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".env")
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write_runtime(values: Mapping[str, str], runtime: Path = RUNTIME, target: Target = STAGING) -> None:
    api_rows = [("MONGO_URL", values["MONGO_URL"]), ("JWT_SECRET", values["JWT_SECRET"]),
                ("INVITE_CODE", values["INVITE_CODE"]), *target.static_env]
    write_private(runtime / API_ENV.name, env_lines(api_rows))
    write_private(runtime / TUNNEL_ENV.name, env_lines([("TUNNEL_TOKEN", values["TUNNEL_TOKEN"])]))


def _common_hardening(service: dict, user: str) -> bool:
    return (service.get("platform") == "linux/arm64" and service.get("user") == user
            and service.get("read_only") is True and service.get("init") is True
            and service.get("cap_drop") == ["ALL"]
            and "no-new-privileges:true" in service.get("security_opt", [])
            and not service.get("privileged") and not service.get("volumes")
            and not service.get("devices") and service.get("network_mode") not in ("host",)
            and service.get("pid") != "host")


def _env_ok(service: dict, path: Path, keys: frozenset[str]) -> bool:
    """Compose may echo env_file paths or inline them into environment."""
    rows = service.get("env_file") or []
    files = [row.get("path") if isinstance(row, dict) else row for row in rows]
    if files and files != [str(path)]:
        return False
    environment = service.get("environment") or {}
    if isinstance(environment, list):
        environment = dict(item.partition("=")[::2] for item in environment)
    if not isinstance(environment, dict):
        return False
    if not files and set(environment) != keys:
        return False
    return set(environment) <= keys


API_ENV_KEYS = frozenset({"MONGO_URL", "JWT_SECRET", "INVITE_CODE", *(k for k, _ in STATIC_API_ENV)})
TUNNEL_ENV_KEYS = frozenset({"TUNNEL_TOKEN"})


def assert_compose(config: dict, digest: str, target: Target = STAGING) -> None:
    if not isinstance(config, dict) or config.get("name") != target.project:
        raise ReleaseError("Unexpected Compose project identity")
    if config.get("secrets") or config.get("configs"):
        raise ReleaseError("Unexpected Compose secrets or configs")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != {API, TUNNEL}:
        raise ReleaseError("Compose may manage the Chronicles API and its tunnel only")
    api, tunnel = services[API], services[TUNNEL]
    if api.get("image") != API_IMAGE + digest or not _common_hardening(api, "65532:65532"):
        raise ReleaseError("Unadmitted or unsafe API container config")
    if not _env_ok(api, target.api_env, API_ENV_KEYS):
        raise ReleaseError("API must read only its root-owned env file")
    ports = api.get("ports")
    if (not isinstance(ports, list) or len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1"
            or str(ports[0].get("published")) != str(target.port) or ports[0].get("target") != 8080
            or ports[0].get("protocol", "tcp") != "tcp"):
        raise ReleaseError(f"Chronicles API must bind loopback port {target.port} only")
    if tunnel.get("image") != TUNNEL_IMAGE or not _common_hardening(tunnel, "65532:65532"):
        raise ReleaseError("Unpinned or unsafe tunnel container config")
    if tunnel.get("ports") or not _env_ok(tunnel, target.tunnel_env, TUNNEL_ENV_KEYS):
        raise ReleaseError("Tunnel must publish nothing and read only its env file")


def fixed_compose_args(*parts: str, target: Target = STAGING) -> list[str]:
    return ["docker", "compose", "--project-directory", str(target.compose.parent),
            "-f", str(target.compose), *parts]


def checked_run(runner: Callable, args: list[str], env: Mapping[str, str], *, output: bool = False,
                target: Target = STAGING) -> str:
    try:
        result = runner(args, env=dict(env), cwd=str(target.compose.parent), text=True,
                        capture_output=True, timeout=240)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("Chronicles-only Docker action could not complete") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise ReleaseError("Chronicles-only Docker action failed")
    if output:
        if len(result.stdout) > 500000:
            raise ReleaseError("Docker Compose config exceeded bounded output")
        return result.stdout
    return ""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_local_api(opener=None, target: Target = STAGING) -> None:
    """Loopback only: liveness, then readiness (a real MongoDB ping)."""
    client = opener or build_opener(ProxyHandler({}), NoRedirect())
    for path in ("/api/health", "/api/ready"):
        url = target.local + path
        try:
            with client.open(Request(url, method="GET"), timeout=10) as response:
                if response.geturl() != url or response.status != 200:
                    raise ReleaseError("Unexpected Chronicles API response")
                body = response.read(4097)
        except (OSError, HTTPError, URLError, UnicodeError) as exc:
            raise ReleaseError(f"Chronicles API smoke failed at {path}") from exc
        if len(body) > 4096:
            raise ReleaseError("Chronicles API smoke response too large")


def persist_receipt(state: Path, digest: str, target: Target = STAGING) -> None:
    payload = {"project": target.project, "services": [API, TUNNEL], "digest": digest, "smoke": True,
               "deployedAt": datetime.now(timezone.utc).isoformat()}
    fd, name = tempfile.mkstemp(dir=state, prefix=".verified-", suffix=".json")
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, state / "last-verified-api.json")
    except OSError as exc:
        raise ReleaseError("Unable to commit verified API receipt") from exc
    finally:
        tmp.unlink(missing_ok=True)


def private_dir(path: Path, *, require_root: bool) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ReleaseError("Unsafe private directory")
    meta = path.stat()
    if (require_root and meta.st_uid != 0) or meta.st_mode & 0o077:
        raise ReleaseError("Private directory must remain root-only")


def deploy(
    digest: str, vault_id: str, environment: str = "staging", *, runner: Callable = subprocess.run,
    guard: Callable = verify_shared_a1_containers, smoke: Callable | None = None,
    bundle_reader: Callable = read_bundle, state: Path | None = None, runtime: Path | None = None,
    policy: Path | None = None, require_root: bool = True,
) -> str:
    validate_request("deploy", digest, vault_id, environment)
    target = TARGETS[environment]
    state = state or target.state
    runtime = runtime or target.runtime
    policy = policy or target.compose
    smoke = smoke or (lambda: verify_local_api(target=target))
    if require_root and os.geteuid() != 0:
        raise ReleaseError("Chronicles API deployer requires root")
    if policy != target.compose:
        raise ReleaseError("Only the installed fixed Compose policy is permitted")
    if require_root:
        check_root_file(policy)
    private_dir(state, require_root=require_root)
    private_dir(runtime, require_root=require_root)
    values = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "CHRONICLES_API_IMAGE_DIGEST": digest}
    with (state / "deploy.lock").open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            guard(runner)
        except SharedHostError as exc:
            raise ReleaseError("Shared A1 ownership guard rejected host state") from exc
        write_runtime(bundle_reader(vault_id, runner, target), runtime, target)
        config_text = checked_run(runner, fixed_compose_args("config", "--format", "json", target=target),
                                  values, output=True, target=target)
        try:
            config = json.loads(config_text)
        except ValueError as exc:
            raise ReleaseError("Compose configuration returned invalid JSON") from exc
        assert_compose(config, digest, target)
        checked_run(runner, fixed_compose_args("pull", API, TUNNEL, target=target), values, target=target)
        try:
            guard(runner)
        except SharedHostError as exc:
            raise ReleaseError("Shared A1 changed during admission") from exc
        (state / "last-verified-api.json").unlink(missing_ok=True)
        checked_run(runner, fixed_compose_args(
            "up", "--detach", "--wait", "--wait-timeout", "150", "--no-build",
            "--pull", "never", "--remove-orphans", API, TUNNEL, target=target,
        ), values, target=target)
        smoke()
        persist_receipt(state, digest, target)
    return target.marker + " digest=" + digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("deploy",))
    parser.add_argument("digest")
    parser.add_argument("vault_id")
    parser.add_argument("environment", nargs="?", default="staging")
    args = parser.parse_args()
    try:
        digest, vault = validate_request(args.operation, args.digest, args.vault_id, args.environment)
        print(deploy(digest, vault, args.environment))
    except (ReleaseError, BlockingIOError, OSError) as exc:
        print("CHRONICLES_API_OCI_DEPLOY_BLOCKED type=" + type(exc).__name__
              + " reason=" + str(exc)[:120], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
