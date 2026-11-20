"""No private cross-repository artifact access for Bridge Squad handoff."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bridgesquad_source_admission as source
import bridgesquad_source_snapshot as snap

SHA = "a" * 40
HTML = (b'<!doctype html><html lang="es"><head><title>Matthias Bridge Squad '
        b'- ShadowOps</title></head><body>Only protected by CF Pages</body></html>')


class Response(io.BytesIO):
    def __init__(self, body: bytes, url: str, status: int = 200):
        super().__init__(body)
        self.url = url
        self.status = status

    def geturl(self):
        return self.url


class FakeOpener:
    def __init__(self, *, body=HTML, redirect=None, status=200):
        self.body = body
        self.redirect = redirect
        self.status = status
        self.calls = []

    def open(self, req, timeout):
        self.calls.append((req.full_url, req.get_header("Authorization"), timeout))
        return Response(self.body, self.redirect or req.full_url, self.status)


class SnapshotTests(unittest.TestCase):
    def test_download_immutable_sha_only_without_auth_or_actions_artifact(self):
        client = FakeOpener()
        self.assertEqual(snap.download(SHA, opener=client), HTML)
        self.assertEqual(client.calls, [
            (f"https://raw.githubusercontent.com/{source.SOURCE}/{SHA}/index.html", None, 15)
        ])
        self.assertNotIn("/actions/", snap.RAW)
        for sha in ("main", "HEAD", "../other", "A"*40, "a"*39, "a"*41):
            with self.subTest(sha=sha), self.assertRaises(snap.Refused):
                snap.download(sha, opener=client)
        self.assertEqual(len(client.calls), 1)

    def test_redirect_non200_invalid_html_oversized_are_denied(self):
        with self.assertRaises(snap.Refused):
            snap.download(SHA, opener=FakeOpener(redirect="https://evil.example/file"))
        with self.assertRaises(snap.Refused):
            snap.download(SHA, opener=FakeOpener(status=404))
        for html in (b"bad", b"\xff"*75, HTML + b"x"*source.MAX_HTML):
            with self.subTest(length=len(html)), self.assertRaises(snap.Refused):
                snap.download(SHA, opener=FakeOpener(body=html))

    def test_rebuilt_archive_matches_game_release_contract_and_zip_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "source.zip"
            receipt = snap.snapshot(SHA, file, fetch=lambda sha: HTML)
            self.assertEqual(receipt["source_sha"], SHA)
            digest = "sha256:" + hashlib.sha256(file.read_bytes()).hexdigest()
            self.assertEqual(receipt["snapshot_digest"], digest)
            self.assertEqual(source.verify_archive(file, digest, SHA)["html_bytes"], len(HTML))
            with zipfile.ZipFile(file) as z:
                self.assertEqual(set(z.namelist()), {"index.html", "release.json"})
                self.assertEqual(z.read("index.html"), HTML)
                manifest = json.loads(z.read("release.json"))
                self.assertEqual(manifest["files"]["index.html"]["sha256"],
                                 hashlib.sha256(HTML).hexdigest())
                self.assertEqual(manifest["authentication"],
                                 {"provider": "shadowops-id", "audience": "bridgesquad", "required": True})
            with self.assertRaises(snap.Refused):
                snap.snapshot(SHA, file, fetch=lambda sha: HTML)
            self.assertEqual(file.read_bytes(), snap.archive_bytes(SHA, HTML))

    def test_invalid_snapshot_no_partial_file_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "snapshot.zip"
            for invalid in (b"bad", HTML + b"z" * source.MAX_HTML):
                with self.subTest(size=len(invalid)), self.assertRaises(snap.Refused):
                    snap.snapshot(SHA, target, fetch=lambda sha: invalid)
                self.assertFalse(target.exists())
            target.write_bytes(b"do-not-overwrite")
            with self.assertRaises(snap.Refused):
                snap.snapshot(SHA, target, fetch=lambda sha: HTML)
            self.assertEqual(target.read_bytes(), b"do-not-overwrite")
            target.unlink()
            target.symlink_to(root / "missing")
            with self.assertRaises(snap.Refused):
                snap.snapshot(SHA, target, fetch=lambda sha: HTML)


if __name__ == "__main__":
    unittest.main()
