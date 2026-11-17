import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_release_package as pkg
import bridgesquad_source_admission as source

SHA = "a" * 40
HTML = b"<!doctype html><html lang='es'><head><title>Matthias Bridge Squad - ShadowOps</title></head><body>Bridge</body></html>"


def original_manifest():
    return {
        "schema": 1, "application": "matthias-bridge-squad", "environment": "production",
        "source_repository": source.SOURCE, "source_sha": SHA,
        "authentication": pkg.AUTH, "files": {
            "index.html": {"sha256": hashlib.sha256(HTML).hexdigest(), "bytes": len(HTML)},
        },
    }


def archive(content=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.html", HTML)
        z.writestr("release.json", json.dumps(content if content is not None else original_manifest()))
    return buffer.getvalue()


class BridgeSquadSealedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.zip = self.root / "original.zip"
        raw = archive()
        self.zip.write_bytes(raw)
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.dest = self.root / "sealed"

    def prepare(self):
        return pkg.prepare(self.zip, self.digest, SHA, self.dest)

    def test_seals_source_html_with_only_reviewed_edge_and_release_manifest(self):
        receipt = self.prepare()
        self.assertEqual(receipt["source_sha"], SHA)
        self.assertEqual(receipt["source_artifact_digest"], self.digest)
        self.assertEqual(receipt["authentication"], {
            "provider": "shadowops-id", "audience": "bridgesquad", "required": True,
        })
        self.assertEqual({p.name for p in self.dest.iterdir()},
                         {"index.html", "_worker.js", "release.json"})
        self.assertEqual((self.dest/"index.html").read_bytes(), HTML)
        self.assertEqual((self.dest/"_worker.js").read_bytes(), pkg.EDGE.read_bytes())
        self.assertEqual(json.loads((self.dest/"release.json").read_text()),receipt)
        self.assertEqual(pkg.verify(self.dest,self.digest,SHA),receipt)
        self.assertEqual(receipt["files"]["_worker.js"]["sha256"],
                         hashlib.sha256(pkg.EDGE.read_bytes()).hexdigest())

    def test_wrong_source_digest_and_cross_environment_fail_before_creation(self):
        for digest, sha in [
            ("sha256:" + "0"*64, SHA),
            (self.digest, "b"*40),
            ("bad", SHA),
        ]:
            with self.subTest(digest=digest,sha=sha), self.assertRaises(pkg.PackageError):
                pkg.prepare(self.zip,digest,sha,self.dest)
            self.assertFalse(self.dest.exists())
        for mutation in (
            {"authentication": {"provider":"shadowops-id","audience":"football","required":True}},
            {"environment":"staging"},
            {"source_sha":"b"*40},
            {"files":{}},
        ):
            row=original_manifest();row.update(mutation)
            raw=archive(row)
            self.zip.write_bytes(raw)
            changed_digest="sha256:"+hashlib.sha256(raw).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(pkg.PackageError):
                pkg.prepare(self.zip,changed_digest,SHA,self.dest)
            self.assertFalse(self.dest.exists())

    def test_refuses_existing_output_and_symlink(self):
        self.dest.mkdir()
        (self.dest/"unrelated.txt").write_text("original")
        with self.assertRaises(pkg.PackageError):
            self.prepare()
        self.assertEqual((self.dest/"unrelated.txt").read_text(),"original")
        (self.dest/"unrelated.txt").unlink()
        self.dest.rmdir()
        self.dest.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(pkg.PackageError):
            self.prepare()

    def test_modified_html_worker_or_release_manifest_cannot_verify(self):
        self.prepare()
        for file, corrupt in [
            ("index.html", b"new HTML"),
            ("_worker.js", b"export default {fetch:()=>new Response('open')}"),
            ("release.json", b"{}"),
        ]:
            target=self.dest/file
            previous=target.read_bytes()
            target.write_bytes(corrupt)
            with self.subTest(file=file), self.assertRaises(pkg.PackageError):
                pkg.verify(self.dest,self.digest,SHA)
            target.write_bytes(previous)
        for filename in ("other.js","_routes.json"):
            path=self.dest/filename
            path.write_text("bypass")
            with self.assertRaises(pkg.PackageError):
                pkg.verify(self.dest,self.digest,SHA)
            path.unlink()

    def test_changing_audited_edge_after_package_invalidates_release(self):
        self.prepare()
        different=self.root/"candidate_worker.js"
        different.write_bytes(pkg.EDGE.read_bytes()+b"\n// changed")
        with mock.patch.object(pkg,"EDGE",different):
            with self.assertRaises(pkg.PackageError):
                pkg.verify(self.dest,self.digest,SHA)

    def test_untrusted_or_symlinked_worker_cannot_be_packaged(self):
        invalid=self.root/"bad_worker.js"
        invalid.write_text("export default {fetch:()=>new Response('guest')}")
        with mock.patch.object(pkg,"EDGE",invalid):
            with self.assertRaises(pkg.PackageError):
                self.prepare()
        symlink=self.root/"linked_worker.js"
        symlink.symlink_to(pkg.EDGE)
        with mock.patch.object(pkg,"EDGE",symlink):
            with self.assertRaises(pkg.PackageError):
                self.prepare()
        self.assertFalse(self.dest.exists())

    def test_manifest_tampering_or_subject_scope_change_fails_verification(self):
        self.prepare()
        path=self.dest/"release.json"
        original=json.loads(path.read_text())
        for change in (
            {"source_artifact_digest":"sha256:"+"0"*64},
            {"authentication":{"provider":"shadowops-id","audience":"bridgesquad","required":False}},
            {"source_sha":"b"*40},
            {"environment":"staging"},
            {"schema":True},
        ):
            update=dict(original);update.update(change)
            path.write_text(json.dumps(update))
            with self.subTest(change=change), self.assertRaises(pkg.PackageError):
                pkg.verify(self.dest,self.digest,SHA)
        path.write_text(json.dumps(original))
        self.assertEqual(pkg.verify(self.dest,self.digest,SHA), original)


if __name__=="__main__":
    unittest.main()
