#!/usr/bin/env python3
"""Chromium proof for exact sealed HTML + real audited Worker, synthetic Identity.

No DNS or external browser traffic: route ALL requests to a 127.0.0.1 Node
fixture serving genuine sealed _worker.js with ephemeral signed Ed25519 JWT.
This verifies compatibility, NOT production provisioning or real login.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

HOST = "https://bridgesquad.shadowops.dpdns.org"
IDENTITY = "https://id.shadowops.dpdns.org"
ALIAS = "https://bridgesquad-production.pages.dev"


def exchange(port: int, path: str, payload: dict) -> dict:
    contents = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=contents,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise AssertionError("oversized fixture response")
    return json.loads(data)


def setup_routes(context, port: int, rejected: list) -> None:
    def routed(route):
        request = route.request
        url = request.url
        if not any(url.startswith(prefix) for prefix in
                   (HOST + "/", IDENTITY + "/", ALIAS + "/")):
            rejected.append(url)
            route.abort()
            return
        raw = request.post_data_buffer
        message = {
            "url": url,
            "method": request.method,
            "headers": request.all_headers(),
            "body": base64.b64encode(raw).decode() if raw else "",
        }
        reply = exchange(port, "/request", message)
        if "error" in reply:
            raise AssertionError("sealed Worker fixture rejected request: " + reply["error"])
        route.fulfill(
            status=reply["status"], headers=reply["headers"],
            body=base64.b64decode(reply["body"]),
        )
    context.route("**/*", routed)


def run(bundle: Path) -> None:
    if (bundle.is_symlink() or not bundle.is_dir() or
            {p.name for p in bundle.iterdir()} !=
            {"_worker.js", "index.html", "release.json"}):
        raise AssertionError("exact three-file sealed bundle required")

    bridge = subprocess.Popen(
        ["node", str(Path(__file__).with_name("bridgesquad_sealed_worker_fixture.mjs")),
         str(bundle.resolve())],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "NODE_NO_WARNINGS": "1"},
    )
    try:
        assert bridge.stdout is not None
        ready, _, _ = select.select([bridge.stdout], [], [], 12)
        if not ready:
            raise AssertionError("local signed Worker fixture did not start")
        metadata = json.loads(bridge.stdout.readline())
        port = metadata["fixture_port"]
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise AssertionError("invalid loopback fixture port")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                for width, height in ((390, 844), (1440, 900)):
                    context = browser.new_context(viewport={"width": width, "height": height})
                    rejected = []
                    setup_routes(context, port, rejected)
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda err: errors.append(str(err)))

                    # Anonymous game HTML / manifests remain blocked by
                    # THE EXACT sealed Worker rather than a fake HTTP stub.
                    guest = page.goto(HOST + "/")
                    assert guest is not None and guest.status == 401
                    assert "ShadowOps ID" in page.locator("h1").inner_text()
                    denied = page.evaluate("""async () => {
                      const r=await fetch('/release.json',{cache:'no-store'});
                      return r.status;
                    }""")
                    assert denied == 401, denied
                    alias = page.goto(ALIAS + "/")
                    assert alias is not None and alias.status == 404

                    # A synthetic HttpOnly IdP cookie stands for a login:
                    # the real Worker + browser bootstrap must exchange it
                    # for a signed Ed25519 JWT and app-only HttpOnly cookie.
                    context.add_cookies([{
                        "name": "__Host-shadowops-id", "value": "synthetic",
                        "url": IDENTITY + "/", "secure": True,
                        "httpOnly": True, "sameSite": "None",
                    }])
                    page.goto(HOST + "/")
                    page.wait_for_function(
                        "window.__MBS_TEST__ && __MBS_TEST__.getState() === 'menu'",
                        timeout=14000,
                    )
                    cookie_names = [c["name"] for c in context.cookies()]
                    assert "__Host-bridgesquad" in cookie_names, cookie_names
                    assert page.evaluate("""
                      Object.keys(localStorage).every(k=>!k.includes('token')&&!k.includes('jwt'))
                    """)
                    manifest = page.evaluate("""async () => {
                      const r=await fetch('/release.json',{cache:'no-store'});
                      return {status:r.status, content: await r.json()};
                    }""")
                    assert manifest["status"] == 200
                    assert manifest["content"]["authentication"]["required"] is True

                    # The unmodified, SEALED game must actually start and
                    # animate under the first-party secure Worker session.
                    page.locator('[data-action="play"]').click()
                    page.wait_for_function("__MBS_TEST__.getState() === 'playing'")
                    page.wait_for_function(
                        "__MBS_TEST__.getSnapshot().world > 1", timeout=8000,
                    )
                    before = page.evaluate("__MBS_TEST__.getIdentity().expiresAt")
                    page.wait_for_timeout(1150)
                    page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
                    page.wait_for_function(
                        "(older) => __MBS_TEST__.getIdentity().expiresAt > older",
                        arg=before, timeout=14000,
                    )
                    assert page.evaluate("__MBS_TEST__.getState()") == "playing"
                    assert not errors, errors

                    # Real Worker authorization is rechecked against signed
                    # token freshness. Revocation may not leak static assets.
                    exchange(port, "/control", {"action": "revoke"})
                    revoked = page.evaluate("async () => (await fetch('/release.json',{cache:'no-store'})).status")
                    assert revoked == 401, revoked
                    page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
                    page.wait_for_function(
                        "__MBS_TEST__.getState() === 'auth-blocked'",
                        timeout=14000,
                    )
                    assert not page.evaluate("__MBS_TEST__.getIdentity().verified")
                    assert not rejected, rejected
                    assert not errors, errors
                    page.close()
                    context.close()
                    exchange(port, "/control", {"action": "reset"})
                    print(f"OK sealed-worker Chromium {width}x{height}: guest 401, alias 404, "
                          "signed login, actual game, silent renewal, revoked deny")
            finally:
                browser.close()
    finally:
        bridge.terminate()
        try:
            bridge.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            bridge.kill()
            bridge.communicate(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: bridgesquad_sealed_worker_browser.py BUNDLE_DIR")
    run(Path(sys.argv[1]))
