"""Signed source release is repackaged with trusted Infra worker, never rebuilt."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_release_package as package

SHA = "a" * 40

def make_zip(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return out.getvalue()

class PackagerTests(unittest.TestCase):
    def test_exact_source_zip_gets_audited_worker_and_immutable_receipt(self):
        original = {"index.html": b"<html>game</html>",
                    "assets/bundle.js": b"const buildSha='" + SHA.encode() + b"';console.log('works')",
                    "assets/style.css": b"body{}"}
        binary = make_zip(original)
        receipt = "sha256:" + hashlib.sha256(binary).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "source.zip"
            artifact.write_bytes(binary)
            dest = Path(tmp) / "release"
            result = package.prepare(artifact, receipt, SHA, dest)
            self.assertEqual(result["authentication"], package.AUTH)
            self.assertEqual(result["source_sha"], SHA)
            for name, raw in original.items():
                self.assertEqual((dest / name).read_bytes(), raw)
            self.assertEqual((dest / "_worker.js").read_bytes(), package.EDGE.read_bytes())
            self.assertEqual(package.verify(dest, SHA, receipt), result)
            with self.assertRaises(package.PackageError):
                package.prepare(artifact, receipt, SHA, dest)
            with self.assertRaises(package.PackageError):
                package.verify(dest, "b" * 40, receipt)

    def test_wrong_source_digest_or_source_supplied_worker_is_rejected(self):
        for files in (
            {"index.html": b"a", "assets/app.js": b"b", "_worker.js": b"guest"},
            {"index.html": b"a", "assets/app.js": b"b", "../escape": b"evil"},
            {"index.html": b"a", "assets/app.js": b"b", "release.json": b"fake"},
        ):
            data = make_zip(files)
            with tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / "source.zip"
                archive.write_bytes(data)
                h = "sha256:" + hashlib.sha256(data).hexdigest()
                with self.subTest(files=files), self.assertRaises(package.PackageError):
                    package.prepare(archive, h, SHA, Path(tmp) / "out")
        safe = make_zip({"index.html": b"a", "assets/app.js": b"b"})
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "source.zip"
            archive.write_bytes(safe)
            with self.assertRaises(package.PackageError):
                package.prepare(archive, "sha256:" + "0" * 64, SHA, Path(tmp) / "out")

    def test_wrong_runtime_sha_is_rejected_before_writing_release(self):
        for runtime in (b"console.log('old build')", b"const sha='" + b"b" * 40 + b"'"):
            data = make_zip({"index.html": b"a", "assets/app.js": runtime})
            receipt = "sha256:" + hashlib.sha256(data).hexdigest()
            with tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / "source.zip"
                archive.write_bytes(data)
                target = Path(tmp) / "release"
                with self.subTest(runtime=runtime), self.assertRaisesRegex(
                    package.PackageError, "does not embed"):
                    package.prepare(archive, receipt, SHA, target)
                self.assertFalse(target.exists(), "a wrong bundle must not leave a release candidate")

    def test_any_runtime_or_worker_tampering_is_detected(self):
        original_js = b"const sourceSha='" + SHA.encode() + b"'"
        data = make_zip({"index.html": b"a", "assets/app.js": original_js})
        receipt = "sha256:" + hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "source.zip"
            archive.write_bytes(data)
            target = Path(tmp) / "release"
            package.prepare(archive, receipt, SHA, target)
            (target / "assets/app.js").write_bytes(b"poison")
            with self.assertRaises(package.PackageError):
                package.verify(target, SHA, receipt)
            (target / "assets/app.js").write_bytes(original_js)
            (target / "_worker.js").write_bytes(b"no auth")
            with self.assertRaises(package.PackageError):
                package.verify(target, SHA, receipt)

if __name__ == "__main__":
    unittest.main()
