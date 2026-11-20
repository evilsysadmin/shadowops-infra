"""Disposable end-to-end signed-JWT/real-Worker fixture tests (no browser)."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "edge/bridgesquad-identity-gate.mjs"
FIXTURE = ROOT / "scripts/bridgesquad_sealed_worker_fixture.mjs"
HOST = "https://bridgesquad.shadowops.dpdns.org"
ID = "https://id.shadowops.dpdns.org"


def call(port, path, payload):
    message = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=message,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.loads(response.read())


def send(port, url, method="GET", headers=None, body=None):
    result = call(port, "/request", {
        "url": url, "method": method, "headers": headers or {},
        "body": base64.b64encode(json.dumps(body).encode()).decode() if body else "",
    })
    if "error" in result:
        raise AssertionError(result["error"])
    result["decoded"] = base64.b64decode(result["body"])
    return result


class SealedFixtureTests(unittest.TestCase):
    def test_actual_worker_denies_guests_and_accepts_only_live_signed_jwt(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            html = (b"<!doctype html><html><title>Matthias Bridge Squad - synthetic"
                    b"</title><body>Real sealed Worker test</body></html>")
            edge = EDGE.read_bytes()
            (target / "index.html").write_bytes(html)
            (target / "_worker.js").write_bytes(edge)
            def sha(data):
                return hashlib.sha256(data).hexdigest()
            manifest = {
                "environment": "production",
                "authentication": {"provider": "shadowops-id",
                                   "audience": "bridgesquad", "required": True},
                "files": {"index.html": {"sha256": sha(html)},
                          "_worker.js": {"sha256": sha(edge)}},
            }
            (target / "release.json").write_text(json.dumps(manifest))
            bridge = subprocess.Popen(
                ["node", str(FIXTURE), str(target)], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                ready, _, _ = select.select([bridge.stdout], [], [], 10)
                self.assertTrue(ready, "local signed Identity fixture not ready")
                port = json.loads(bridge.stdout.readline())["fixture_port"]
                self.assertEqual(send(port, HOST + "/")["status"], 401)
                self.assertEqual(send(port, HOST + "/release.json")["status"], 401)
                self.assertEqual(send(port, "https://bridgesquad-production.pages.dev/")["status"], 404)

                # No IdP cookie, no token; signed token cannot be invented by
                # the browser, and Edge won't serve anything anonymously.
                self.assertEqual(send(port, ID + "/api/identity/token", method="POST",
                    headers={"origin": HOST})["status"], 401)
                token_response = send(port, ID + "/api/identity/token", method="POST",
                    headers={"origin": HOST, "cookie": "__Host-shadowops-id=synthetic"})
                self.assertEqual(token_response["status"], 200)
                token = json.loads(token_response["decoded"])["token"]
                handshake = send(port, HOST + "/api/bridgesquad/session", method="POST",
                    headers={"origin": HOST, "content-type": "application/json"},
                    body={"token": token})
                self.assertEqual(handshake["status"], 200)
                cookie = handshake["headers"]["set-cookie"]
                self.assertIn("HttpOnly", cookie)
                self.assertIn("Secure", cookie)
                self.assertIn("SameSite=Lax", cookie)
                sess_cookie = cookie.split(";", 1)[0]
                served = send(port, HOST + "/index.html",
                              headers={"cookie": sess_cookie})
                self.assertEqual(served["status"], 200)
                self.assertEqual(served["decoded"], html)
                release = send(port, HOST + "/release.json",
                               headers={"cookie": sess_cookie})
                self.assertEqual(release["status"], 200)
                self.assertTrue(json.loads(release["decoded"])["authentication"]["required"])
                self.assertEqual(send(port, HOST + "/release.json")["status"], 401)

                # Real Worker must query synthetic live revocation on every
                # request, even though EdDSA JWT remains valid.
                call(port, "/control", {"action": "revoke"})
                revoked = send(port, HOST + "/index.html", headers={"cookie": sess_cookie})
                self.assertEqual(revoked["status"], 401)
                denied = send(port, HOST + "/release.json",
                              headers={"cookie": sess_cookie})
                self.assertEqual(denied["status"], 401)
                print("BRIDGESQUAD_SEALED_WORKER_SIGNED_FIXTURE_OK guest-denied signed-EdDSA revoked")
            finally:
                bridge.terminate()
                try:
                    bridge.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    bridge.kill()
                    bridge.communicate(timeout=5)

    def test_missing_or_tampered_sealed_bundle_cannot_start(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run(
                ["node", str(FIXTURE), folder], capture_output=True,
                text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("fixture_port", result.stdout)


if __name__ == "__main__":
    unittest.main()
