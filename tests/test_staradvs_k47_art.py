"""Offline contract checks for the manual-only original K-47 immutable publisher."""
import hashlib
import io
import tempfile
import urllib.error
import json
from pathlib import Path
import struct
import sys
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import staradvs_k47_art as art

SOURCE = "a" * 40


def minimal_glb(uri=None):
    data = {"asset": {"version": "2.0"},
            "meshes": [{"primitives": [{"attributes": {"POSITION": 0}}]}],
            "buffers": [{"byteLength": 4}]}
    if uri:
        data["buffers"][0]["uri"] = uri
    json_bytes = json.dumps(data).encode()
    json_bytes += b" " * ((-len(json_bytes)) % 4)
    chunk = b"\0\0\0\0"
    length = 12 + 8 + len(json_bytes) + 8 + len(chunk)
    return (struct.pack("<III", 0x46546c67, 2, length)
            + struct.pack("<II", len(json_bytes), 0x4E4F534A)
            + json_bytes + struct.pack("<II", 4, 0x004E4942) + chunk)


def make_bundle(*, mutate=None, missing=None, bad_external=False):
    slot_rows = []
    assets = {}
    indexes = []
    size = 0
    for name, cells, anchor in art.SLOTS:
        blob = minimal_glb("https://untrusted.example/ext.bin") if (bad_external and
                name == art.SLOTS[0][0]) else minimal_glb()
        digest = hashlib.sha256(blob).hexdigest()
        basename = f"{name}-{digest[:16]}.glb"
        data = {
            "id": name, "footprint": [list(c) for c in cells],
            "anchor": list(anchor), "status": "published",
            "asset": {
                "url": art.CDN + basename, "sha256": digest,
                "bytes": len(blob), "license": "original",
                "source": "Original author-created ShadowOps building",
            },
        }
        slot_rows.append(data)
        path = "k47-art-candidate/assets/" + basename
        assets[path] = blob
        indexes.append({"key": "assets/" + basename, "sha256": digest,
                        "bytes": len(blob), "id": name})
        size += len(blob)
    manifest = {"schemaVersion": 1, "scene": "meridian.surface", "slots": slot_rows}
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    receipt = {"schemaVersion": 1, "sourceSha": SOURCE, "modelCount": 3,
               "bytes": size, "sha256sums": indexes,
               "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
               "published": False, "visualAcceptance": "independent verified screenshots"}
    if mutate:
        mutate(manifest, receipt, assets)
        manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
        receipt["manifestSha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("k47-art-candidate/manifest.candidate.json", manifest_bytes)
        z.writestr("k47-art-candidate/receipt.json", json.dumps(receipt))
        for key, data in assets.items():
            z.writestr(key, data)
        for filename in sorted(art.EXPECTED_SHOTS):
            if filename == missing:
                continue
            width = int(filename.rsplit("-", 1)[-1].split(".")[0])
            png = b"\x89PNG\r\n\x1a\n" + b"\0" * 8 + struct.pack(">II", width, 850) + b"more"
            z.writestr(filename, png)
    return output.getvalue()


class VerifiedGlbReleaseTest(unittest.TestCase):
    def test_three_original_manifest_assets_and_actual_viewports(self):
        manifest, entries = art.verify_archive(make_bundle(), SOURCE)
        self.assertEqual(len(manifest["slots"]), 3)
        self.assertEqual(set(entries), {art.PREFIX + slot[0] + "-" +
          hashlib.sha256(minimal_glb()).hexdigest()[:16] + ".glb"
          for slot in art.SLOTS})
        self.assertTrue(all(art.PREFIX in key for key in entries))

    def test_wrong_sha_rejected_without_cloud(self):
        with self.assertRaisesRegex(art.PublishError, "source SHA"):
            art.verify_archive(make_bundle(), "main")

    def test_missing_full_sector_screenshot_blocks_release(self):
        with self.assertRaisesRegex(art.PublishError, "visual captures"):
            art.verify_archive(make_bundle(missing=next(iter(art.EXPECTED_SHOTS))), SOURCE)

    def test_tampered_original_bytes_block_release(self):
        def mutate(manifest, receipt, assets):
            first = next(iter(assets))
            assets[first] += b"tampered"
        with self.assertRaisesRegex(art.PublishError, "GLB bytes"):
            art.verify_archive(make_bundle(mutate=mutate), SOURCE)

    def test_path_cannot_escape_artifact(self):
        self.assertRaisesRegex(art.PublishError, "source artifact ZIP",
                               art.verify_archive, b"PK", SOURCE)
        raw = make_bundle()
        z = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as before:
            with zipfile.ZipFile(z, "w") as after:
                for item in before.namelist():
                    after.writestr(item, before.read(item))
                after.writestr("../secret", b"bad")
        with self.assertRaisesRegex(art.PublishError, "unsafe ZIP entry"):
            art.verify_archive(z.getvalue(), SOURCE)

    def test_external_glb_resource_blocks_publication(self):
        with self.assertRaisesRegex(art.PublishError, "externally dependent"):
            art.verify_archive(make_bundle(bad_external=True), SOURCE)

    def test_mutated_manifest_uri_cannot_choose_foreign_r2_key(self):
        def mutate(manifest, receipt, assets):
            manifest["slots"][0]["asset"]["url"] = "https://elsewhere.example/a.glb"
        with self.assertRaisesRegex(art.PublishError, "immutable CDN path"):
            art.verify_archive(make_bundle(mutate=mutate), SOURCE)


    def test_public_cdn_probe_absent_objects_are_pending_not_approved(self):
        _, entries = art.verify_archive(make_bundle(), SOURCE)
        class Missing:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        with patch.object(art.urllib.request, "build_opener", return_value=Missing()):
            self.assertEqual(art.public_probe(entries), sorted(entries))
            with self.assertRaisesRegex(art.PublishError, "missing"):
                art.public_verify(entries)

    def test_public_probe_distinguishes_tampered_bytes_from_missing(self):
        _, entries = art.verify_archive(make_bundle(), SOURCE)
        class Response:
            status = 200
            def __init__(self, request, payload, content_type="model/gltf-binary"):
                self.request, self.payload = request, payload
                from email.message import Message
                self.headers = Message()
                self.headers["Content-Type"] = content_type
                self.headers["Cache-Control"] = art.CACHE
                self.headers["Access-Control-Allow-Origin"] = art.ORIGIN
            def geturl(self):
                return self.request.full_url
            def read(self, length):
                return self.payload[:length]
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
        class MockCDN:
            def __init__(self, status="valid"):
                self.status = status
            def open(self, request, timeout):
                key = request.full_url.removeprefix(
                    "https://assets.chess-studio.shadowops.dpdns.org/")
                payload = entries[key]
                if self.status == "bad-bytes":
                    payload = payload[:-1] + b"X"
                return Response(request, payload,
                    "application/octet-stream" if self.status == "bad-mime"
                    else "model/gltf-binary")
        with patch.object(art.urllib.request, "build_opener", return_value=MockCDN()):
            self.assertEqual(art.public_probe(entries), [])
            art.public_verify(entries)
        with patch.object(art.urllib.request, "build_opener", return_value=MockCDN("bad-bytes")):
            with self.assertRaisesRegex(art.PublishError, "SHA mismatch"):
                art.public_probe(entries)
        with patch.object(art.urllib.request, "build_opener", return_value=MockCDN("bad-mime")):
            with self.assertRaisesRegex(art.PublishError, "HTTP/CORS"):
                art.public_probe(entries)

    def test_public_evidence_is_not_activation_approval(self):
        manifest, entries = art.verify_archive(make_bundle(), SOURCE)
        receipt = art.public_activation_evidence(SOURCE, manifest, entries)
        self.assertTrue(receipt["cdnPublicBytesVerified"])
        self.assertFalse(receipt["humanVisualApproval"])
        self.assertFalse(receipt["activationDone"])
        self.assertEqual(receipt["manifest"], manifest)
        self.assertEqual(len(receipt["models"]), 3)
        self.assertEqual({x["sha256"] for x in receipt["models"]},
                         {hashlib.sha256(blob).hexdigest() for blob in entries.values()})

    def test_probe_writes_evidence_only_after_all_public_bytes_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            z = root / "source.zip"
            output = root / "public-proof.json"
            z.write_bytes(make_bundle())
            command = ["staradvs_k47_art.py", "probe", "--source-sha", SOURCE,
                       "--artifact", str(z), "--out", str(output)]
            with patch.object(sys, "argv", command), patch.object(
                    art, "public_probe", return_value=[art.PREFIX + "missing.glb"]):
                self.assertEqual(art.main(), 0)
                self.assertFalse(output.exists())
            with patch.object(sys, "argv", command), patch.object(
                    art, "public_probe", return_value=[]):
                self.assertEqual(art.main(), 0)
                data = json.loads(output.read_text())
                self.assertTrue(data["cdnPublicBytesVerified"])
                self.assertFalse(data["activationDone"])


if __name__ == "__main__":
    unittest.main()
