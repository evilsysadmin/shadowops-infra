"""Fail-closed offline R2 immutable uploader tests (no AWS or Cloudflare calls)."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_r2_immutable as r2
import pawn_action_web_package as pkg
from pawn_action_source_admission import AdmissionError

SHA = "a" * 40


class Conflict(Exception):
    response = {"Error": {"Code": "PreconditionFailed"}}


class FakeS3:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.puts = []
        self.list_calls = 0
        self.conflict = False
        self.broken_inventory = False

    def list_objects_v2(self, **args):
        self.list_calls += 1
        if self.broken_inventory:
            return {"Contents": [{"Key": "foreign", "Size": -9}], "IsTruncated": False}
        assert args["Bucket"] == r2.BUCKET
        return {"IsTruncated": False, "Contents": [
            {"Key": k, "Size": len(v)} for k, v in self.objects.items()
        ]}

    def get_object(self, *, Bucket, Key):
        assert Bucket == r2.BUCKET
        if Key not in self.objects:
            raise KeyError(Key)
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, **args):
        assert args["Bucket"] == r2.BUCKET
        assert args["Key"].startswith("pawn-action/releases/")
        assert args["IfNoneMatch"] == "*"
        assert args["Key"] != "pawn-action/current.json"
        self.puts.append(args["Key"])
        if self.conflict or args["Key"] in self.objects:
            raise Conflict()
        self.objects[args["Key"]] = args["Body"]


def fixture(root: Path):
    out = root / "candidate"
    web = {"index.html": b"<html>Pawn Action</html>",
           "index.js": b"console.log('start')",
           "index.wasm": b"\0asm" * 40,
           "index.pck": b"pck" * 100}
    zipfile_path = root / "source.zip"
    with zipfile.ZipFile(zipfile_path, "w") as z:
        for key, data in web.items():
            z.writestr(key, data)
    digest = "sha256:" + hashlib.sha256(zipfile_path.read_bytes()).hexdigest()
    manifest = pkg.prepare(zipfile_path, digest, SHA, 41, 42, out)
    receipt = {
        "source_sha": SHA, "run_id": 41, "artifact_id": 42,
        "artifact_digest": digest, "visual_artifact_id": 77,
        "visual_artifact_digest": "sha256:" + "b" * 64,
    }
    return out, manifest, receipt


class ImmutablePublisherTests(unittest.TestCase):
    def test_create_only_exact_keys_idempotent_and_pointer_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out, manifest, receipt = fixture(root)
            client = FakeS3({"chess-studio/stays.bin": b"original"})
            first = r2.upload_immutable(client, out, SHA, receipt)
            self.assertEqual(first["uploaded"], 4)
            self.assertEqual(first["reused"], 0)
            self.assertEqual(client.objects["chess-studio/stays.bin"], b"original")
            self.assertEqual(len(client.puts), 4)
            self.assertNotIn("pawn-action/current.json", client.objects)
            self.assertFalse(any(x.startswith("pawn-slug-godot/") for x in client.puts))
            again = r2.upload_immutable(client, out, SHA, receipt)
            self.assertEqual(again["uploaded"], 0)
            self.assertEqual(again["reused"], 4)
            self.assertEqual(len(client.puts), 4)

    def test_existing_corrupt_key_prevents_all_writes(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            key = manifest["files"]["index.js"]["key"]
            client = FakeS3({key: b"bad bytes"})
            with self.assertRaises(AdmissionError):
                r2.upload_immutable(client, out, SHA, receipt)
            self.assertEqual(client.puts, [])

    def test_invalid_source_receipt_prevents_inventory_and_writes(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            for bad in ("source_sha", "artifact_id", "artifact_digest", "visual_artifact_id"):
                client = FakeS3()
                changed = dict(receipt)
                changed[bad] = None
                with self.subTest(bad=bad), self.assertRaises(AdmissionError):
                    r2.upload_immutable(client, out, SHA, changed)
                self.assertEqual(client.list_calls, 0)
                self.assertEqual(client.puts, [])

    def test_inventory_invalid_and_capacity_fails_before_any_put(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            corrupt = FakeS3()
            corrupt.broken_inventory = True
            with self.assertRaises(AdmissionError):
                r2.upload_immutable(corrupt, out, SHA, receipt)
            self.assertEqual(corrupt.puts, [])
            _, entries = r2._entries(out, SHA)
            huge = {"other/bytes": r2.SHARED_SOFT_LIMIT}
            with self.assertRaises(AdmissionError):
                r2.budget(huge, entries)
            with self.assertRaises(AdmissionError):
                r2.budget({"pawn-action/legacy.bin": r2.OWN_SOFT_LIMIT}, entries)

    def test_create_once_collision_never_overwrites_foreign_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            client = FakeS3()
            client.conflict = True
            with self.assertRaises(AdmissionError):
                r2.upload_immutable(client, out, SHA, receipt)
            self.assertEqual(client.objects, {})
            self.assertEqual(len(client.puts), 1)

    def test_source_candidate_changed_and_nonrelease_key_block(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            path = out / "runtime/index.wasm"
            path.write_bytes(b"foreign")
            with self.assertRaises(AdmissionError):
                r2.upload_immutable(FakeS3(), out, SHA, receipt)
            path.write_bytes(b"\0asm" * 40)
            forged = dict(manifest)
            forged["files"] = {k: dict(v) for k, v in manifest["files"].items()}
            forged["files"]["index.wasm"]["key"] = "pawn-slug-godot/current.json"
            (out / "release.json").write_text(json.dumps(forged))
            with self.assertRaises(AdmissionError):
                r2._entries(out, SHA)

    def test_pagination_truncated_or_wrong_cursor_fails_closed(self):
        class StaleCursor(FakeS3):
            def list_objects_v2(self, **kwargs):
                return {"Contents": [], "IsTruncated": True,
                        "NextContinuationToken": "loop"}
        with self.assertRaises(AdmissionError):
            r2.inventory(StaleCursor())

    def test_public_bucket_cli_apply_retires_before_identity_or_cloud_io(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            arguments = ["pawn_action_r2_immutable.py", "apply", "--candidate", str(out),
                         "--source-sha", SHA, "--confirm-immutable-upload",
                         r2.PREFIX + manifest["release"]]
            with patch.object(sys, "argv", arguments), \\
                 patch.object(r2, "GithubReader") as reader, \\
                 patch.object(r2, "admit") as admit, \\
                 patch.object(r2, "create_client") as client:
                self.assertEqual(r2.main(), 1)
                reader.assert_not_called()
                admit.assert_not_called()
                client.assert_not_called()

    def test_plan_is_offline_and_does_not_require_aws_secret(self):
        with tempfile.TemporaryDirectory() as td:
            out, manifest, receipt = fixture(Path(td))
            m, entries = r2._entries(out, SHA)
            self.assertFalse(m["publishAuthorized"])
            self.assertEqual(set(e[1]["key"] for e in entries.values()),
                             {x["key"] for x in m["files"].values()})
            with self.assertRaises(AdmissionError):
                r2.create_client({})

if __name__ == "__main__":
    unittest.main()
