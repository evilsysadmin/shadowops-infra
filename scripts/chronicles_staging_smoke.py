#!/usr/bin/env python3
"""End-to-end smoke of the Chronicles API after a staging deploy.

Plays the path a player takes, through the public hostname: register a
throwaway account, start a run, read its world, save a checkpoint, read it
back, sync progression, and finally delete the account (always, even when a
step fails). Readiness alone proves MongoDB answers; this proves saving works.

The invite code comes from the existing GitHub secret and is never printed;
neither is the throwaway password or any token. Output is one line per step.

Usage:
    python3 scripts/chronicles_staging_smoke.py                      # in CI
    CHRONICLES_SMOKE_API=http://localhost:8090/api INVITE_CODE=... \
        python3 scripts/chronicles_staging_smoke.py                  # locally
    python3 scripts/chronicles_staging_smoke.py --self-test
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from typing import Callable, Mapping

DEFAULT_API = "https://chronicles-api-staging.shadowops.dpdns.org/api"
USER_AGENT = "shadowops-infra-chronicles-smoke/1"
MARKER = "CHRONICLES_STAGING_E2E_SMOKE_OK"


class SmokeError(RuntimeError):
    pass


class Client:
    def __init__(self, base: str, opener: Callable = urllib.request.urlopen):
        self.base, self.opener, self.token = base.rstrip("/"), opener, ""

    def call(self, method: str, path: str, body: object | None = None) -> tuple[int, dict]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener(request, timeout=30) as response:
                raw = response.read(2_000_000)
                return response.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read(20_000) or b"{}")
            except ValueError:
                return error.code, {}

    def expect(self, step: str, method: str, path: str, body: object | None = None) -> dict:
        code, payload = self.call(method, path, body)
        if not 200 <= code < 300:
            detail = payload.get("detail") if isinstance(payload, dict) else ""
            raise SmokeError(f"{step}: HTTP {code} {str(detail)[:160]!r}")
        print(f"ok {step}")
        return payload if isinstance(payload, dict) else {}


def smoke(env: Mapping[str, str], opener: Callable = urllib.request.urlopen) -> str:
    invite = str(env.get("INVITE_CODE", "")).strip()
    if not invite:
        raise SmokeError("INVITE_CODE is required")
    client = Client(str(env.get("CHRONICLES_SMOKE_API") or DEFAULT_API), opener)
    client.expect("ready", "GET", "/ready")
    username = "smoke-" + secrets.token_hex(4)
    password = secrets.token_urlsafe(18)
    registered = client.expect("register", "POST", "/auth/register", {
        "username": username, "password": password, "email": f"{username}@example.com", "inviteCode": invite,
    })
    client.token = str(registered.get("token") or "")
    if not client.token:
        raise SmokeError("register: no session token")
    try:
        # Staging must never promote a freshly registered ordinary account
        # while activating a reviewed central-only administrator.
        me = client.expect("ordinary session", "GET", "/auth/me")
        if me.get("isAdmin") is not False:
            raise SmokeError("ordinary session has unexpected administrator privileges")
        roster_status, _ = client.call("GET", "/chronicles/admin/users")
        if roster_status != 403:
            raise SmokeError(f"ordinary account admin roster: HTTP {roster_status}, expected 403")
        print("ok admin boundary: ordinary account denied")

        created = client.expect("create run", "POST", "/chronicles/runs", {})
        run_id = str(created.get("runId") or created.get("run", {}).get("runId") or "")
        if not run_id:
            raise SmokeError("create run: no runId")
        boot = client.expect("bootstrap", "GET", f"/chronicles/runs/{run_id}/bootstrap")
        world_version, map_id = _world(boot)
        client.expect("checkpoint", "PUT", f"/chronicles/runs/{run_id}/checkpoint", {
            "expectedWorldVersion": world_version, "currentMapId": map_id,
            "worldFlags": {"__chrRuntime.smoke": "1"}, "inventory": {}, "quests": {},
            "consumedContentIds": [], "claimedRewards": [],
        })
        again = client.expect("reload", "GET", f"/chronicles/runs/{run_id}/bootstrap")
        reloaded_version, _ = _world(again)
        if reloaded_version <= world_version:
            raise SmokeError(f"reload: world version did not advance ({world_version} -> {reloaded_version})")
        if "__chrRuntime.smoke" not in json.dumps(again):
            raise SmokeError("reload: the saved flag did not come back")
        client.expect("progression", "PUT", "/chronicles/progression",
                      {"progression": {"version": 1, "heroes": {"matthias": {"xp": 1}}}, "baseRevision": 0})
        progression = client.expect("progression read", "GET", "/chronicles/progression")
        if progression.get("revision") != 1:
            raise SmokeError("progression read: revision did not persist")
    finally:
        # Never leave the throwaway account behind.
        client.expect("delete account", "POST", "/auth/delete-account", {"password": password})
    return f"{MARKER} user={username}"


def _world(boot: dict) -> tuple[int, str]:
    run = boot.get("run") if isinstance(boot.get("run"), dict) else boot
    version = run.get("worldVersion", boot.get("worldVersion"))
    map_id = run.get("currentMapId", boot.get("currentMapId"))
    if not isinstance(version, int) or not isinstance(map_id, str) or not map_id:
        raise SmokeError("bootstrap: missing worldVersion/currentMapId")
    return version, map_id


def self_test() -> None:
    state = {"version": 1, "flags": {}, "deleted": False, "auth": [],
             "admin": False, "roster_open": False, "me_missing": False}

    class Response:
        def __init__(self, status: int, body: dict):
            self.status, self.body = status, body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _limit=None):
            return json.dumps(self.body).encode()

    def opener(request, timeout):
        path = request.full_url.split("/api", 1)[1]
        body = json.loads(request.data) if request.data else None
        state["auth"].append(request.headers.get("Authorization", ""))
        if path == "/ready":
            return Response(200, {"status": "ready"})
        if path == "/auth/register":
            assert body["inviteCode"] == "code"
            return Response(200, {"token": "t", "username": body["username"]})
        if path == "/auth/me":
            return Response(200, {} if state["me_missing"] else {"isAdmin": state["admin"]})
        if path == "/chronicles/admin/users":
            return Response(200 if state["roster_open"] else 403,
                            {"users": [{"username": "private"}]} if state["roster_open"] else {})
        if path == "/chronicles/runs":
            return Response(201, {"run": {"runId": "r1"}})
        if path.endswith("/bootstrap"):
            return Response(200, {"run": {"worldVersion": state["version"], "currentMapId": "swordhaven",
                                          "worldFlags": state["flags"]}})
        if path.endswith("/checkpoint"):
            assert body["expectedWorldVersion"] == state["version"]
            state["version"] += 1
            state["flags"] = body["worldFlags"]
            return Response(200, {})
        if path == "/chronicles/progression":
            return Response(200, {"revision": 1})
        if path == "/auth/delete-account":
            state["deleted"] = True
            return Response(200, {"deleted": True})
        raise AssertionError(path)

    assert smoke({"INVITE_CODE": "code"}, opener).startswith(MARKER)
    assert state["deleted"] and state["auth"][-1] == "Bearer t"

    # If an unrelated player can become admin, view the roster or if the
    # /auth/me contract stops reporting privileges, fail and clean up.
    for flag in ("admin", "roster_open", "me_missing"):
        state.update(version=1, flags={}, deleted=False)
        state[flag] = True
        try:
            smoke({"INVITE_CODE": "code"}, opener)
        except SmokeError as error:
            assert ("admin" in str(error).lower() or "administrator" in str(error).lower())
        else:
            raise AssertionError(f"unsafe {flag} state passed admin boundary")
        assert state["deleted"], f"account not deleted on {flag} failure"
        state[flag] = False

    # A failing step still deletes the account.
    state.update(version=1, flags={}, deleted=False)

    def broken(request, timeout):
        if request.full_url.endswith("/checkpoint"):
            raise urllib.error.HTTPError(request.full_url, 500, "boom", {}, None)
        return opener(request, timeout)

    try:
        smoke({"INVITE_CODE": "code"}, broken)
    except SmokeError:
        pass
    else:
        raise AssertionError("broken checkpoint passed")
    assert state["deleted"]
    print("chronicles_staging_smoke self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        raise SystemExit(0)
    try:
        print(smoke(os.environ))
    except SmokeError as error:
        print(f"CHRONICLES_STAGING_E2E_SMOKE_FAILED {error}")
        raise SystemExit(1)
