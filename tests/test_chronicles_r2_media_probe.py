"""Offline contracts for the manual public-media R2 cutover proof."""
from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_media_probe as p


class MediaProbeTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.bytes = {asset: (asset.name.encode() * (asset.size // len(asset.name) + 1))[:asset.size]
                      for asset in p.PINS}

    def fetch(self, method, asset):
        self.calls.append((method, asset.name))
        age = "31536000, immutable" if asset.versioned else "3600"
        headers = {
            "content-type": asset.mime,
            "access-control-allow-origin": p.ORIGIN,
            "cache-control": "public, max-age=" + age,
            "content-length": str(asset.size),
        }
        return 200, headers, self.bytes[asset] if method == "GET" else b""

    def test_exact_four_chronicles_pins_and_fixed_source_hashes(self):
        self.assertEqual(len(p.PINS), 4)
        self.assertEqual(sum(x.size for x in p.PINS), 12793710)
        self.assertEqual({x.name for x in p.PINS},
                         {"first-verse", "second-verse", "party-master", "party-runtime"})
        for asset in p.PINS:
            self.assertTrue(asset.key.startswith("chronicles/"))
            self.assertLess(asset.size, p.MAX_OBJECT_BYTES)
            self.assertEqual(len(asset.sha256), 64)
        self.assertEqual(p.HOST, "assets.chronicles.shadowops.dpdns.org")

    def test_full_success_reads_only_head_and_get_for_four_fixed_objects(self):
        with patch.object(p, "PINS", tuple(
            p.Asset(a.name, a.key, a.size, hashlib.sha256(self.bytes[a]).hexdigest(),
                    a.mime, a.versioned) for a in p.PINS
        )):
            # Keep fixtures indexed by asset identity even when SHA pins are patched.
            original = {a.name: blob for a, blob in self.bytes.items()}
            def fetch(method, asset):
                source = next(a for a in self.bytes if a.name == asset.name)
                status, headers, _ = self.fetch(method, source)
                return status, headers, original[asset.name] if method == "GET" else b""
            result = p.probe(fetch)
        self.assertEqual(result["status"], "ready-for-manual-review")
        self.assertEqual(result["assets"], 4)
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(self.calls[0][0], "HEAD")
        self.assertEqual(self.calls[1][0], "GET")

    def test_rejects_wrong_mime_cors_size_and_status(self):
        asset = p.PINS[0]
        status, headers, body = self.fetch("GET", asset)
        for changed_status, changed_headers, changed_body in (
            (302, headers, body),
            (200, {**headers, "content-type": "text/html"}, body),
            (200, {**headers, "access-control-allow-origin": "https://evil.example"}, body),
            (200, {**headers, "content-length": "1"}, body),
            (200, headers, body[:-1]),
            (200, headers, b"x" * len(body)),
        ):
            with self.subTest(case=(changed_status, changed_headers, len(changed_body))):
                with self.assertRaises(p.ProbeError):
                    p.validate(changed_status, changed_headers, asset, changed_body)

    def test_rejects_unsafe_cache_policies(self):
        for asset in p.PINS:
            status, headers, _ = self.fetch("HEAD", asset)
            invalid = ("public, max-age=31536000, immutable" if not asset.versioned
                       else "public, max-age=600")
            for cache in (invalid, "private, max-age=3600", "public, max-age=xx",
                          "public, max-age=3600, max-age=500", ""):
                with self.subTest(asset=asset.name, cache=cache):
                    with self.assertRaises(p.ProbeError):
                        p.validate(status, {**headers, "cache-control": cache}, asset)

    def test_rejects_changed_bytes_even_with_matching_length(self):
        asset = p.PINS[1]
        status, headers, body = self.fetch("GET", asset)
        with self.assertRaisesRegex(p.ProbeError, "SHA-256"):
            p.validate(status, headers, asset, body)

    def test_no_unbounded_or_mutating_transport(self):
        source = pathlib.Path(p.__file__).read_text()
        for banned in ('method="POST"', 'method="PUT"', 'method="DELETE"',
                       'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', "subprocess."):
            self.assertNotIn(banned, source)
        self.assertIn("class _NoRedirects", source)
        self.assertIn("response.read(asset.size + 1)", source)
        self.assertIn('f"https://{HOST}/{key}"', source)

    def test_live_probe_runs_only_on_explicit_manual_dispatch(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-r2-media-proof.yml").read_text()
        live = workflow.split("\n  live:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", live)
        self.assertIn("github.ref == 'refs/heads/main'", live)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", live)
        self.assertIn("needs: contracts", live)
        self.assertIn("scripts/chronicles_r2_media_probe.py", live)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("  schedule:", workflow)


if __name__ == "__main__":
    unittest.main()
