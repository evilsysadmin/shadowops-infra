#!/usr/bin/env python3
"""Delete ONE Chronicles staging account so its owner can register again.

Runs in GitHub Actions only (manual dispatch from protected main). Staging has
no email recovery, so an account whose password no longer works cannot be
recovered; its owner asks for it to be removed instead.

The API exposes POST /api/ops/delete-account on staging only, authorised by a
short-lived HS256 operator token signed with the API's JWT secret. This script
mints that token from the GitHub secret and calls the endpoint once. It never
prints the secret or the token: only the username and the API's answer.

Usage:
    python3 scripts/chronicles_staging_delete_account.py           # in CI
    python3 scripts/chronicles_staging_delete_account.py --self-test
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Mapping

API = "https://chronicles-api-staging.shadowops.dpdns.org/api/ops/delete-account"
PURPOSE = "ops_delete_account"
LIFETIME_SECONDS = 300
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")
CONFIRMATION = "BORRAR"


class DeleteError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_token(secret: str, username: str, now: float) -> str:
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64(json.dumps(
        {"sub": username, "purpose": PURPOSE, "exp": int(now) + LIFETIME_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


def read_inputs(env: Mapping[str, str]) -> tuple[str, str]:
    secret = str(env.get("CHRONICLES_STAGING_JWT_SECRET", ""))
    if len(secret.strip()) < 32:
        raise DeleteError("Missing or short GitHub secret CHRONICLES_STAGING_JWT_SECRET")
    username = str(env.get("TARGET_USERNAME", "")).strip().lower()
    if not USERNAME_RE.fullmatch(username):
        raise DeleteError("username must be 3-64 chars: a-z, 0-9, '_', '.', '-'")
    if str(env.get("CONFIRMATION", "")).strip() != CONFIRMATION:
        raise DeleteError(f"confirmation must be exactly {CONFIRMATION}")
    # The API trims the secret it reads; sign with the same bytes.
    return secret.strip(), username


def call_api(token: str, username: str, opener: Callable = urllib.request.urlopen) -> tuple[int, dict]:
    request = urllib.request.Request(
        API,
        data=json.dumps({"username": username}).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with opener(request, timeout=20) as response:
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
        print(f"CHRONICLES_STAGING_DELETE_FAILED status={status} detail={detail!r}")
        return 1
    print(f"CHRONICLES_STAGING_ACCOUNT_DELETED username={username} deleted={body.get('deleted')} games={body.get('deletedGames')}")
    return 0


def self_test() -> None:
    secret = "s" * 40
    token = mint_token(secret, "evilsysadmin", 1_800_000_000)
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims == {"sub": "evilsysadmin", "purpose": PURPOSE, "exp": 1_800_000_000 + LIFETIME_SECONDS}
    expected = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    assert signature == _b64(expected)
    good = {"CHRONICLES_STAGING_JWT_SECRET": secret, "TARGET_USERNAME": " EvilSysAdmin ", "CONFIRMATION": "BORRAR"}
    assert read_inputs(good) == (secret, "evilsysadmin")
    for bad in (
        {**good, "CHRONICLES_STAGING_JWT_SECRET": "short"},
        {**good, "TARGET_USERNAME": "a"},
        {**good, "TARGET_USERNAME": "x' or 1=1"},
        {**good, "CONFIRMATION": "si"},
    ):
        try:
            read_inputs(bad)
        except DeleteError:
            continue
        raise AssertionError(f"accepted {bad}")

    class Response:
        def __init__(self, status: int, body: dict):
            self.status, self._body = status, body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps(self._body).encode()

    seen = {}

    def opener(request, timeout):
        seen["auth"] = request.headers.get("Authorization", "")
        seen["body"] = json.loads(request.data)
        return Response(200, {"deleted": True, "username": "evilsysadmin", "deletedGames": 0})

    assert run(good, opener, lambda: 1_800_000_000) == 0
    assert seen["body"] == {"username": "evilsysadmin"} and seen["auth"].startswith("Bearer ")
    print("chronicles_staging_delete_account self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        raise SystemExit(0)
    try:
        raise SystemExit(run(os.environ))
    except DeleteError as error:
        print(f"CHRONICLES_STAGING_DELETE_REFUSED {error}")
        raise SystemExit(2)
