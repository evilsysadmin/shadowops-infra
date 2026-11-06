"""Offline and mutation-free tests for Pawn Action's locked public perimeter."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_staging_surface as surface

STATUS = {"application": "pawn-action", "environment": "staging", "state": "locked", "game_ready": False}


def locked(path, method):
    headers = {"Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff"}
    if path == surface.STATUS:
        import json
        return 200, {**headers, "Content-Type": "application/json; charset=utf-8"}, json.dumps(STATUS).encode()
    return 503, headers, b""


class SurfaceTests(unittest.TestCase):
    def test_exact_locked_surface_and_no_credentialed_requests(self):
        calls = []
        def request(path, method):
            calls.append((path, method))
            return locked(path, method)
        result = surface.inspect(request)
        self.assertEqual(result["state"], "locked")
        self.assertFalse(result["gameReady"])
        self.assertFalse(result["published"])
        self.assertEqual(len(calls), 1 + 2 * len(surface.DENIED))
        self.assertGreaterEqual(len(surface.DENIED), 16)
        self.assertEqual(calls[0], ("/_shadowops/status", "GET"))
        self.assertNotIn("https://assets.chess-studio.shadowops.dpdns.org", surface.BASE)
        self.assertIn(("/index.wasm", "GET"), calls)
        self.assertIn(("/index.wasm", "HEAD"), calls)
        self.assertIn(("/_shadowops/session.js", "GET"), calls)
        self.assertIn(("/api/pawn-action/session", "HEAD"), calls)

    def test_private_worker_asset_allowlist_is_completely_covered(self):
        """Do not claim a locked surface when a newly added Godot file leaks."""
        worker = (Path(__file__).resolve().parents[1] /
                  "workers/pawn-action-staging/private-delivery.mjs").read_text(
                      encoding="utf-8")
        match = re.search(r"const FILES = Object\.freeze\(\{(.*?)\n\}\);", worker, re.S)
        self.assertIsNotNone(match, "Private Worker FILES allowlist changed shape")
        files = set(re.findall(r"^\s*'([^']+)':", match.group(1), re.M))
        self.assertGreaterEqual(len(files), 9)
        self.assertEqual(files, {
            item.removeprefix("/") for item in surface.DENIED
            if item.startswith("/index.") and item not in ("/index.html",)
        } | {"index.html"})

    def test_absent_or_wrong_identity_status_fails(self):
        import json
        variants = [
            {**STATUS, "game_ready": True},
            {**STATUS, "state": "ready"},
            {**STATUS, "application": "football"},
            {**STATUS, "environment": "production"},
            {**STATUS, "extra": "unexpected"},
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                def wrong(path, method):
                    status, headers, body = locked(path, method)
                    if path == surface.STATUS:
                        body = json.dumps(variant).encode()
                    return status, headers, body
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.inspect(wrong)

    def test_public_wasm_or_legacy_pointer_is_never_ok(self):
        for target in ("/index.wasm", "/index.pck", "/pawn-slug-godot/current.json", "/"):
            with self.subTest(target=target):
                def exposed(path, method):
                    if path == target and method == "HEAD":
                        return 200, locked(path, method)[1], b""
                    return locked(path, method)
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.inspect(exposed)

    def test_get_exposure_even_when_head_is_denied(self):
        for target in ("/index.wasm", "/index.pck", "/index.js", "/pawn-action/current.json",
                       "/index.audio.worklet.js", "/index.apple-touch-icon.png",
                       "/_shadowops/session.js", "/api/pawn-action/session",
                       "/pawn-action/releases/0000000000000000/index.wasm"):
            with self.subTest(target=target):
                def exposed(path, method):
                    if path == target and method == "GET":
                        return 200, locked(path, method)[1], b""
                    return locked(path, method)
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.inspect(exposed)

    def test_redirect_cache_or_missing_security_headers_fails(self):
        faults = [
            (302, {"Location": "https://assets.chess-studio.shadowops.dpdns.org/"}),
            (503, {"Cache-Control": "public, max-age=3600"}),
            (503, {"X-Content-Type-Options": "none"}),
        ]
        for code, patch in faults:
            with self.subTest(code=code, patch=patch):
                def broken(path, method):
                    status, headers, body = locked(path, method)
                    if path == "/" and method == "GET":
                        headers = {**headers, **patch}
                        return code, headers, body
                    return status, headers, body
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.inspect(broken)

    def test_status_rejects_unbounded_or_invalid_body(self):
        for body in (b"{"*5000, b"not json", b"[]"):
            with self.subTest(size=len(body)):
                def bad(path, method):
                    code, headers, value = locked(path, method)
                    return code, headers, body if path == surface.STATUS else value
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.inspect(bad)

    def test_no_arbitrary_hosts_or_methods(self):
        for path, method in (("https://attacker.tld/", "GET"), ("/index.wasm?x=1", "HEAD"),
                             ("/_shadowops/status", "POST"), ("/", "DELETE")):
            with self.subTest(path=path, method=method):
                with self.assertRaises(surface.SurfaceBlocked):
                    surface.fetch(path, method)


if __name__ == "__main__":
    unittest.main()
