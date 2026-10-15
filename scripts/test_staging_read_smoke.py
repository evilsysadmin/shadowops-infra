"""Local mock contract tests for the read-only staging smoke."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from staging_read_smoke import (  # noqa: E402
    SmokeError, local_base_url, read_private_token, verify_staging_reads,
)

ALICE = "alice-synthetic-jwt"
BOB = "bob-synthetic-jwt"


class FixtureAPI(BaseHTTPRequestHandler):
    bad_owner = False

    def log_message(self, *_args):
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if self.path in {"/healthz", "/readyz"}:
            return self.answer(200, {"status": "ready"})
        if self.path.startswith("/api/chronicles/runs"):
            if auth not in {"Bearer " + ALICE, "Bearer " + BOB}:
                return self.answer(401, {"detail": "No autenticado."})
            owner = auth == "Bearer " + ALICE
            if self.path == "/api/chronicles/runs":
                runs = (
                    [{"runId": "fixture-run", "currentMapId": "crypt",
                      "worldVersion": 2, "status": "active", "updatedAtMs": 1000}]
                    if owner or self.bad_owner else []
                )
                return self.answer(200, {"runs": runs})
            if self.path == "/api/chronicles/runs/fixture-run" and owner:
                return self.answer(200, {
                    "runId": "fixture-run", "currentMapId": "crypt",
                    "worldVersion": 2, "worldFlags": {"door": True},
                    "inventory": {"key": {"quantity": 1}},
                    "quests": {"q": {"status": "active"}},
                })
        return self.answer(404, {"detail": "Not found"})

    def answer(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StagingSmokeTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureAPI)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_staged_reads_pass_without_modifying_state(self):
        verify_staging_reads(self.base, ALICE, BOB, "fixture-run", "crypt")

    def test_rejects_wrong_map_and_same_identity(self):
        with self.assertRaisesRegex(SmokeError, "identity or map"):
            verify_staging_reads(self.base, ALICE, BOB, "fixture-run", "other-map")
        with self.assertRaisesRegex(SmokeError, "two different"):
            verify_staging_reads(self.base, ALICE, ALICE, "fixture-run", "crypt")

    def test_rejects_owner_data_leak(self):
        class LeakyFixture(FixtureAPI):
            bad_owner = True

        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LeakyFixture)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        with self.assertRaisesRegex(SmokeError, "cross-account"):
            verify_staging_reads(self.base, ALICE, BOB, "fixture-run", "crypt")

    def test_rejects_remote_or_malformed_urls(self):
        for value in (
            "https://example.org", "http://example.org:1234",
            "http://127.0.0.1", "http://user:password@localhost:8080",
            "http://localhost:8080/other", "http://localhost:8080/?x=1",
        ):
            with self.subTest(value=value), self.assertRaises(SmokeError):
                local_base_url(value)
        self.assertEqual(local_base_url(self.base), self.base)

    def test_requires_private_regular_token_files(self):
        with tempfile.TemporaryDirectory() as folder:
            token = Path(folder) / "token"
            token.write_text(ALICE + "\n")
            os.chmod(token, 0o600)
            self.assertEqual(read_private_token(str(token)), ALICE)
            os.chmod(token, 0o644)
            with self.assertRaises(SmokeError):
                read_private_token(str(token))
            os.chmod(token, 0o600)
            link = Path(folder) / "link"
            link.symlink_to(token)
            with self.assertRaises(SmokeError):
                read_private_token(str(link))
            with self.assertRaises(SmokeError):
                read_private_token(str(Path(folder) / "missing"))


if __name__ == "__main__":
    unittest.main()
