#!/usr/bin/env python3
"""Read-only smoke test for a locally forwarded Chronicles staging API.

The test never sends modifying HTTP methods. Supply two synthetic staging
account tokens and one fixture run created by the staging provisioning step.
No token, response body or customer data is printed.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class SmokeError(Exception):
    """A staging-read admission requirement failed."""


def local_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise SmokeError("staging smoke requires an explicit loopback HTTP URL")
    return f"http://{parsed.hostname}:{parsed.port}"


def read_private_token(path: str) -> str:
    file = Path(path)
    if file.is_symlink():
        raise SmokeError("token file must not be a symlink")
    try:
        metadata = file.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise SmokeError("token file must be private and regular (mode 0600 or 0400)")
        if metadata.st_size < 10 or metadata.st_size > 4096:
            raise SmokeError("token file size is invalid")
        token = file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise SmokeError("cannot read the private staging token file") from exc
    if len(token) < 10 or any(char.isspace() for char in token):
        raise SmokeError("invalid token contents")
    return token


def request_get(base: str, path: str, token: str | None) -> tuple[int, bytes]:
    request = Request(
        base + path,
        headers={"Authorization": f"Bearer {token}"} if token else {},
        method="GET",
    )
    try:
        with urlopen(request, timeout=6) as response:
            return response.status, response.read(1_000_001)
    except HTTPError as exc:
        try:
            return exc.code, exc.read(1_000_001)
        finally:
            exc.close()
    except (URLError, TimeoutError, OSError) as exc:
        raise SmokeError(f"staging HTTP request failed: {path}") from exc


def expect_status(result: tuple[int, bytes], expected: int, path: str) -> bytes:
    status, body = result
    if status != expected:
        raise SmokeError(f"{path}: expected HTTP {expected}, received {status}")
    if len(body) > 1_000_000:
        raise SmokeError(f"{path}: response exceeds smoke size limit")
    return body


def decoded_object(body: bytes, path: str) -> dict:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeError(f"{path}: response is not JSON") from exc
    if not isinstance(value, dict):
        raise SmokeError(f"{path}: expected a JSON object")
    return value


def verify_staging_reads(
    base_url: str, owner_token: str, other_token: str, run_id: str, expected_map: str
) -> None:
    base = local_base_url(base_url)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", run_id):
        raise SmokeError("invalid staging fixture run ID")
    if not expected_map or len(expected_map) > 128:
        raise SmokeError("expected fixture map is missing")
    if owner_token == other_token:
        raise SmokeError("two different staging account tokens are required")

    expect_status(request_get(base, "/healthz", None), 200, "/healthz")
    expect_status(request_get(base, "/readyz", None), 200, "/readyz")
    list_path = "/api/chronicles/runs"
    get_path = f"{list_path}/{run_id}"
    expect_status(request_get(base, list_path, None), 401, "anonymous list")
    expect_status(request_get(base, get_path, None), 401, "anonymous read")

    own_list = decoded_object(
        expect_status(request_get(base, list_path, owner_token), 200, "owner list"),
        "owner list",
    )
    own_runs = own_list.get("runs")
    if not isinstance(own_runs, list) or not any(
        isinstance(run, dict) and run.get("runId") == run_id for run in own_runs
    ):
        raise SmokeError("owner's staging fixture does not appear in the run list")

    other_list = decoded_object(
        expect_status(request_get(base, list_path, other_token), 200, "other list"),
        "other list",
    )
    other_runs = other_list.get("runs")
    if not isinstance(other_runs, list) or any(
        isinstance(run, dict) and run.get("runId") == run_id for run in other_runs
    ):
        raise SmokeError("cross-account list isolation failed")

    saved = decoded_object(
        expect_status(request_get(base, get_path, owner_token), 200, "owned run"),
        "owned run",
    )
    if saved.get("runId") != run_id or saved.get("currentMapId") != expected_map:
        raise SmokeError("staging run identity or map was not restored")
    for name in ("worldFlags", "inventory", "quests"):
        if not isinstance(saved.get(name), dict):
            raise SmokeError(f"staging run field {name} is not a JSON object")
    version = saved.get("worldVersion")
    if type(version) is not int or version < 0:
        raise SmokeError("staging run world version is invalid")
    if "owner" in saved or "createFingerprint" in saved:
        raise SmokeError("private storage fields appeared in the public run")

    expect_status(request_get(base, get_path, other_token), 404, "other owner's run")
    expect_status(
        request_get(base, get_path + "/bootstrap", owner_token),
        404,
        "bootstrap route must remain disabled",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18081")
    parser.add_argument("--owner-token-file", required=True)
    parser.add_argument("--other-token-file", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-map", required=True)
    args = parser.parse_args()
    try:
        verify_staging_reads(
            args.base_url,
            read_private_token(args.owner_token_file),
            read_private_token(args.other_token_file),
            args.run_id,
            args.expected_map,
        )
    except SmokeError as exc:
        parser.exit(1, f"Chronicles staging smoke FAILED: {exc}\n")
    print("Chronicles staging read-only smoke PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
