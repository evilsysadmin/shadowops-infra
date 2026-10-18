#!/usr/bin/env python3
"""Import ONE player's Chronicles runs and progression from Chess Studio.

Runs in GitHub Actions only (manual dispatch from protected main). During the
first iteration the game saved through Chess Studio's API, so those runs live
in Chess Studio's staging database. The Chronicles API exposes
POST /api/ops/import-legacy on staging only; it copies the account's runs and
hero progression into Chronicles' database, idempotently and without
overwriting anything.

Authorised by a short-lived HS256 operator token (purpose ops_import_legacy)
signed with the API's JWT secret. Never prints the secret or the token: only
the username and the API's answer.

Usage:
    python3 scripts/chronicles_staging_import_legacy.py           # in CI
    python3 scripts/chronicles_staging_import_legacy.py --self-test
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Mapping

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chronicles_staging_delete_account as ops  # noqa: E402

API = "https://chronicles-api-staging.shadowops.dpdns.org/api/ops/import-legacy"
PURPOSE = "ops_import_legacy"


class ImportError_(RuntimeError):
    pass


def read_inputs(env: Mapping[str, str]) -> tuple[str, str]:
    secret = str(env.get("CHRONICLES_STAGING_JWT_SECRET", ""))
    if len(secret.strip()) < 32:
        raise ImportError_("Missing or short GitHub secret CHRONICLES_STAGING_JWT_SECRET")
    username = str(env.get("TARGET_USERNAME", "")).strip().lower()
    if not ops.USERNAME_RE.fullmatch(username):
        raise ImportError_("username must be 3-64 chars: a-z, 0-9, '_', '.', '-'")
    return secret.strip(), username


def mint_token(secret: str, username: str, now: float) -> str:
    header = ops._b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = ops._b64(json.dumps(
        {"sub": username, "purpose": PURPOSE, "exp": int(now) + ops.LIFETIME_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8"))
    signature = ops.hmac.new(secret.encode("utf-8"), f"{header}.{payload}".encode("ascii"), ops.hashlib.sha256).digest()
    return f"{header}.{payload}.{ops._b64(signature)}"


def call_api(token: str, username: str, opener: Callable = urllib.request.urlopen) -> tuple[int, dict]:
    request = urllib.request.Request(
        API,
        data=json.dumps({"username": username}).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": ops.USER_AGENT},
    )
    try:
        with opener(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read() or b"{}")
        except ValueError:
            body = {}
        return error.code, body


def run(env: Mapping[str, str], opener: Callable = urllib.request.urlopen, now: Callable[[], float] = time.time) -> int:
    secret, username = read_inputs(env)
    status, body = call_api(mint_token(secret, username, now()), username, opener)
    if status != 200:
        detail = str(body.get("detail", ""))[:200] if isinstance(body, dict) else ""
        print(f"CHRONICLES_STAGING_IMPORT_FAILED status={status} detail={detail!r}")
        return 1
    result = body.get("result") if isinstance(body, dict) else {}
    result = result if isinstance(result, dict) else {}
    print(f"CHRONICLES_STAGING_IMPORT_OK username={username} runsImported={result.get('runsImported')} "
          f"runsKept={result.get('runsKept')} progression={result.get('progression')}")
    return 0


def self_test() -> None:
    secret = "s" * 40
    token = mint_token(secret, "evilsysadmin", 1_800_000_000)
    payload = token.split(".")[1]
    claims = json.loads(ops.base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims == {"sub": "evilsysadmin", "purpose": PURPOSE, "exp": 1_800_000_000 + ops.LIFETIME_SECONDS}
    good = {"CHRONICLES_STAGING_JWT_SECRET": secret, "TARGET_USERNAME": " EvilSysAdmin "}
    assert read_inputs(good) == (secret, "evilsysadmin")
    for bad in ({**good, "CHRONICLES_STAGING_JWT_SECRET": "short"}, {**good, "TARGET_USERNAME": "x' or 1=1"}):
        try:
            read_inputs(bad)
        except ImportError_:
            continue
        raise AssertionError(f"accepted {bad}")

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({"username": "evilsysadmin", "result": {"runsImported": 2, "runsKept": 0, "progression": "imported"}}).encode()

    seen = {}

    def opener(request, timeout):
        seen["body"] = json.loads(request.data)
        seen["agent"] = request.get_header("User-agent", "")
        return Response()

    assert run(good, opener, lambda: 1_800_000_000) == 0
    assert seen == {"body": {"username": "evilsysadmin"}, "agent": ops.USER_AGENT}
    print("chronicles_staging_import_legacy self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        raise SystemExit(0)
    try:
        raise SystemExit(run(os.environ))
    except ImportError_ as error:
        print(f"CHRONICLES_STAGING_IMPORT_REFUSED {error}")
        raise SystemExit(2)
