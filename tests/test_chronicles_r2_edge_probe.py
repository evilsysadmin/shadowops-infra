"""No-network contracts for the Chronicles public edge read-only handoff."""
from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_edge_probe as p


class EdgeProbeTests(unittest.TestCase):
    def setUp(self):
        self.body = b"RIFF-pinned-fixture"
        self.headers = {
            "content-type": "image/webp", "access-control-allow-origin": p.ORIGIN,
            "cache-control": "public, immutable, max-age=31536000",
        }
        self.mutable_headers = {
            **self.headers, "cache-control": "public, max-age=14400",
        }
        self.calls = []

    def fetch(self, method, key):
        self.calls.append((method, key))
        if key == p.MUTABLE_KEY:
            return 200, self.mutable_headers, b""
        return 200, self.headers, self.body if method == "GET" else b""

    def test_valid_public_edge_reads_only_expected_fixed_keys(self):
        with patch.object(p, "IMMUTABLE_SIZE", len(self.body)), patch.object(
            p, "IMMUTABLE_SHA256", hashlib.sha256(self.body).hexdigest()
        ):
            self.assertEqual(p.probe(self.fetch)["edge"], "ok")
        self.assertEqual(self.calls, [
            ("HEAD", p.MUTABLE_KEY), ("HEAD", p.IMMUTABLE_KEY), ("GET", p.IMMUTABLE_KEY),
        ])

    def test_mutable_cache_fails_before_pinned_object_request(self):
        for cache in ("public, max-age=31536000", "public, max-age=31536001", "immutable"):
            with self.subTest(cache=cache):
                self.calls.clear()
                self.mutable_headers["cache-control"] = cache
                with self.assertRaisesRegex(p.ProbeError, "mutable alias"):
                    p.probe(self.fetch)
                self.assertEqual(self.calls, [("HEAD", p.MUTABLE_KEY)])

    def test_immutable_head_rejects_mime_cors_cache_size_or_status(self):
        for key, value in (
            ("content-type", "text/html"),
            ("access-control-allow-origin", "https://untrusted.example"),
            ("cache-control", "public, max-age=31536000"),
            ("cache-control", "private, immutable, max-age=31536000"),
            ("cache-control", "public, immutable, max-age=120"),
            ("cache-control", "public, immutable, max-age=31536000, max-age=120"),
            ("content-length", "99"),
        ):
            with self.subTest(key=key, value=value):
                self.calls.clear()
                self.headers = {**self.headers, key: value}
                with self.assertRaises(p.ProbeError):
                    p.probe(self.fetch)
                self.assertEqual(self.calls, [("HEAD", p.MUTABLE_KEY), ("HEAD", p.IMMUTABLE_KEY)])
                self.headers = {"content-type": "image/webp", "access-control-allow-origin": p.ORIGIN,
                                "cache-control": "public, immutable, max-age=31536000"}

    def test_get_fails_for_bad_bytes_bad_headers_or_status(self):
        with patch.object(p, "IMMUTABLE_SIZE", len(self.body)), patch.object(
            p, "IMMUTABLE_SHA256", hashlib.sha256(self.body).hexdigest()
        ):
            for response in (
                (404, self.headers, self.body),
                (200, self.headers, b"x" * len(self.body)),
                (200, self.headers, b"too short"),
                (200, {**self.headers, "content-type": "text/html"}, self.body),
            ):
                def bad_fetch(method, key):
                    return response if method == "GET" else self.fetch(method, key)
                with self.subTest(code=response[0], headers=response[1], size=len(response[2])):
                    with self.assertRaises(p.ProbeError):
                        p.probe(bad_fetch)

    def test_transport_is_fixed_to_https_and_does_not_follow_redirects(self):
        source = pathlib.Path(p.__file__).read_text()
        for banned in ('method="POST"', 'method="PUT"', 'method="DELETE"',
                       'subprocess.', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'):
            self.assertNotIn(banned, source)
        self.assertIn('class _NoRedirects', source)
        self.assertIn('https://{HOST}/{key}', source)
        self.assertEqual(p.HOST, "assets.chronicles.shadowops.dpdns.org")


    def test_public_edge_proof_runs_on_relevant_main_changes_not_unrelated_merges(self):
        workflow = (
            pathlib.Path(__file__).resolve().parents[1] /
            ".github/workflows/chronicles-r2-edge-probe.yml"
        ).read_text(encoding="utf-8")
        expected_paths = {
            "- .github/workflows/chronicles-r2-edge-probe.yml",
            "- scripts/chronicles_r2_edge_probe.py",
            "- tests/test_chronicles_r2_edge_probe.py",
        }
        self.assertIn("  workflow_dispatch:\n", workflow)
        on = workflow.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        pr_paths = on.split("  pull_request:\n    paths:\n", 1)[1].split("  push:\n", 1)[0]
        push_paths = on.split("  push:\n    branches: [main]\n    paths:\n", 1)[1].split(
            "  workflow_dispatch:", 1
        )[0]
        self.assertEqual({line.strip() for line in pr_paths.splitlines()}, expected_paths)
        self.assertEqual({line.strip() for line in push_paths.splitlines()}, expected_paths)
        self.assertNotIn("  schedule:", workflow)
        self.assertNotIn("    - '**'", on)

    def test_public_live_job_requires_main_and_never_receives_secrets(self):
        workflow = (
            pathlib.Path(__file__).resolve().parents[1] /
            ".github/workflows/chronicles-r2-edge-probe.yml"
        ).read_text(encoding="utf-8")
        live = workflow.split("\n  live:\n", 1)[1]
        self.assertIn("    needs: contracts\n", live)
        self.assertIn("github.event_name == 'push'", live)
        self.assertIn("github.event_name == 'workflow_dispatch'", live)
        self.assertIn("github.ref == 'refs/heads/main'", live)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", live)
        self.assertIn("python3 -S scripts/chronicles_r2_edge_probe.py", live)
        self.assertIn("persist-credentials: false", live)
        self.assertIn("  contents: read\n", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("    env:", workflow)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("terraform apply", workflow)


if __name__ == "__main__":
    unittest.main()
