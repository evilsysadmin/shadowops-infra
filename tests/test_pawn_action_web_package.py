"""Offline deterministic Pawn Action staging package tests; no Cloudflare calls."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_web_package as pkg
from pawn_action_source_admission import AdmissionError

SHA = "a" * 40

def archive_bytes(reversed_order=False):
    assets = {
        "index.html": b"<html>Pawn Action</html>",
        "index.js": b"console.log('godot')",
        "index.wasm": b"\0asm" + b"w" * 1024,
        "index.pck": b"p" * 4096,
        "index.audio.worklet.js": b"audio",
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as file:
        for name in sorted(assets, reverse=reversed_order):
            file.writestr(name, assets[name])
    return stream.getvalue()

def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()

class PawnActionPackageTests(unittest.TestCase):
    def test_real_bundle_digest_contract_and_verifiable_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = archive_bytes()
            zip_path = root / "source.zip"
            zip_path.write_bytes(raw)
            out = root / "candidate"
            result = pkg.prepare(zip_path, digest(raw), SHA, 55, 77, out)
            self.assertEqual(pkg.validate(out, SHA), result)
            self.assertEqual(result["index"],
                             f'{pkg.ORIGIN}/pawn-action/releases/{result["release"]}/index.html')
            self.assertEqual(result["sourceArtifact"]["artifactId"], 77)
            self.assertFalse(result["publishAuthorized"])
            self.assertEqual(result["pages"]["filesTooLargeForPages"], [])
            self.assertEqual((out / "runtime/index.pck").read_bytes(), b"p" * 4096)
            self.assertFalse((out / "runtime/current.json").exists())
            self.assertFalse((out / "current.json").exists())

            # Independent reproduction of Pawn Action's actual bundle digest.
            hashing = hashlib.sha256()
            for path in sorted((out / "runtime").iterdir()):
                data = path.read_bytes()
                hashing.update(path.name.encode() + b"\0")
                hashing.update(hashlib.sha256(data).hexdigest().encode() + b"\0")
                hashing.update(str(len(data)).encode() + b"\n")
            self.assertEqual(result["sha256"], hashing.hexdigest())
            self.assertEqual(result["release"], hashing.hexdigest()[:16])

    def test_deterministic_files_even_if_zip_order_differs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a, b = archive_bytes(), archive_bytes(reversed_order=True)
            first, second = root / "a.zip", root / "b.zip"
            first.write_bytes(a)
            second.write_bytes(b)
            x = pkg.prepare(first, digest(a), SHA, 55, 77, root / "a")
            y = pkg.prepare(second, digest(b), SHA, 55, 77, root / "b")
            self.assertEqual(x["release"], y["release"])
            self.assertEqual(x["files"], y["files"])
            self.assertNotEqual(x["sourceArtifact"]["digest"], y["sourceArtifact"]["digest"])

    def test_existing_destination_wrong_digest_or_invalid_source_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = archive_bytes()
            file = root / "web.zip"
            file.write_bytes(raw)
            for bad_digest in ("sha256:" + "0"*64, "bogus"):
                with self.assertRaises(AdmissionError):
                    pkg.prepare(file, bad_digest, SHA, 1, 2, root / "bad")
                self.assertFalse((root / "bad").exists())
            with self.assertRaises(AdmissionError):
                pkg.prepare(file, digest(raw), "b"*7, 1, 2, root / "bad")
            pkg.prepare(file, digest(raw), SHA, 1, 2, root / "candidate")
            with self.assertRaises(AdmissionError):
                pkg.prepare(file, digest(raw), SHA, 1, 2, root / "candidate")

    def test_tampered_runtime_and_manifest_are_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = archive_bytes()
            path = root / "web.zip"
            path.write_bytes(raw)
            out = root / "candidate"
            pkg.prepare(path, digest(raw), SHA, 1, 2, out)
            wasm = out / "runtime/index.wasm"
            wasm.write_bytes(b"foreign WASM")
            with self.assertRaises(AdmissionError):
                pkg.validate(out, SHA)
            pkg.prepare(path, digest(raw), SHA, 1, 2, root / "clean")
            clean = root / "clean"
            manifest = json.loads((clean / "release.json").read_text())
            manifest["pointerKey"] = "pawn-slug-godot/current.json"
            (clean / "release.json").write_text(json.dumps(manifest))
            with self.assertRaises(AdmissionError):
                pkg.validate(clean, SHA)

    def test_oversized_pages_file_is_reported_and_stays_in_runtime(self):
        contents = {"index.html": b"html", "index.js": b"js",
                    "index.pck": b"pck", "index.wasm": b"x" * (pkg.PAGES_FILE_LIMIT + 1)}
        manifest = pkg._build_manifest(contents, SHA, "sha256:" + "a"*64, 1, 2)
        self.assertEqual(manifest["pages"]["filesTooLargeForPages"], ["index.wasm"])
        self.assertEqual(manifest["files"]["index.wasm"]["bytes"], pkg.PAGES_FILE_LIMIT + 1)

if __name__ == "__main__":
    unittest.main()
