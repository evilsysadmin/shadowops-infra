"""Offline-only tests for immutable Pawn Action PRIVATE R2 publishing."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_private_r2_publish as pub
import pawn_action_web_package as pkg
from pawn_action_source_admission import AdmissionError
from cloudflare_control_plane import InventoryError

SHA = "a" * 40
ROOT = "pawn-action/releases/"


def candidate(root: Path, *, extra: dict | None = None):
    content = {"index.html": b"<html>Private Pawn Action</html>",
               "index.js": b"console.log('private')",
               "index.wasm": b"\0asm" + b"w" * 16,
               "index.pck": b"p" * 1024,
               "index.audio.worklet.js": b"worklet"}
    content.update(extra or {})
    archive = root / "source.zip"
    with zipfile.ZipFile(archive, "w") as out:
        for name, data in sorted(content.items()):
            out.writestr(name, data)
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    out = root / "candidate"
    manifest = pkg.prepare(archive, digest, SHA, 42, 43, out)
    receipt = {"source_sha": SHA, "run_id": 42, "artifact_id": 43,
               "artifact_digest": digest, "visual_artifact_id": 44,
               "visual_artifact_digest": "sha256:" + "b" * 64}
    return out, manifest, receipt


class FakePrivateReader:
    account = "a" * 32

    def __init__(self, state="private", *, change_after=0):
        self.state = state
        self.calls = []
        self.change_after = change_after

    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        root = f"/accounts/{self.account}/r2/buckets/{pub.BUCKET}"
        if path == root:
            if self.state == "absent":
                return 404, None
            return 200, {"name": pub.BUCKET}
        if path == root + "/domains/managed":
            # Switch to public when the second post-upload verification runs.
            inspected = sum(p == root for p in self.calls)
            return 200, {"enabled": self.state == "public" or
                         (self.change_after and inspected >= self.change_after)}
        if path == root + "/domains/custom":
            return 200, {"domains": [] if self.state != "custom" else
                         [{"domain": "public.example", "enabled": False}]}
        raise AssertionError(path)


class Collision(Exception):
    response = {"Error": {"Code": "PreconditionFailed"}}


class FakeS3:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.puts = []
        self.reads = []
        self.lists = []
        self.conflict = False
        self.broken = False

    def list_objects_v2(self, **opts):
        assert opts["Bucket"] == pub.BUCKET
        self.lists.append(opts)
        if self.broken:
            return {"IsTruncated": True, "Contents": [],
                    "NextContinuationToken": "loop"}
        return {"IsTruncated": False,
                "Contents": [{"Key": k, "Size": len(v)} for k, v in self.objects.items()]}

    def get_object(self, **opts):
        assert opts["Bucket"] == pub.BUCKET
        self.reads.append(opts["Key"])
        if opts["Key"] not in self.objects:
            raise KeyError("No such private object")
        body = self.objects[opts["Key"]]
        return {"Body": io.BytesIO(body), "ContentLength": len(body)}

    def put_object(self, **opts):
        assert opts["Bucket"] == pub.BUCKET
        assert opts["IfNoneMatch"] == "*"
        assert opts["Key"].startswith(ROOT)
        assert opts["Key"] != "pawn-action/current.json"
        payload = opts["Body"].read()
        assert len(payload) == opts["ContentLength"]
        self.puts.append(opts["Key"])
        if self.conflict or opts["Key"] in self.objects:
            raise Collision()
        self.objects[opts["Key"]] = payload


class PrivatePublisherTests(unittest.TestCase):
    def test_verified_private_bucket_create_once_readback_and_idempotency(self):
        with tempfile.TemporaryDirectory() as d:
            path, manifest, receipt = candidate(Path(d))
            reader, store = FakePrivateReader(), FakeS3()
            first = pub.publish(store, reader, path, SHA, receipt)
            self.assertEqual(first["bucket"], pub.BUCKET)
            self.assertEqual(first["created"], 5)
            self.assertEqual(first["reused"], 0)
            self.assertEqual(len(store.reads), 5)
            self.assertEqual(len(reader.calls), 6, "privacy checked before and after")
            self.assertTrue(all(name.startswith(ROOT) for name in store.objects))
            self.assertFalse(any("current.json" in name for name in store.objects))
            self.assertFalse(any("pawn-slug" in name for name in store.objects))
            self.assertFalse(any("chess-studio" in name for name in store.objects))
            second = pub.publish(store, reader, path, SHA, receipt)
            self.assertEqual(second["created"], 0)
            self.assertEqual(second["reused"], 5)
            self.assertEqual(len(store.puts), 5, "never overwrites existing")
            self.assertEqual(len(store.reads), 10)

    def test_public_absent_and_custom_domain_buckets_have_no_writes(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            for status in ("public", "absent", "custom"):
                with self.subTest(status=status):
                    store = FakeS3()
                    with self.assertRaises((AdmissionError, InventoryError)):
                        pub.publish(store, FakePrivateReader(status), path, SHA, receipt)
                    self.assertEqual(store.puts, [])
                    self.assertEqual(store.lists, [])

    def test_privacy_becomes_public_after_upload_fails_even_if_objects_exist(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            reader, store = FakePrivateReader(change_after=2), FakeS3()
            with self.assertRaises((AdmissionError, InventoryError)):
                pub.publish(store, reader, path, SHA, receipt)
            self.assertEqual(len(store.puts), 5)
            self.assertEqual(len(reader.calls), 5, "stop at failed managed-domain check")
            self.assertFalse(any("current.json" in key for key in store.objects))

    def test_receipt_mismatch_precedes_cloud_read_or_write(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            for key in ("source_sha", "run_id", "artifact_id",
                        "artifact_digest", "visual_artifact_id",
                        "visual_artifact_digest"):
                with self.subTest(field=key):
                    invalid = dict(receipt)
                    invalid[key] = ""
                    reader, store = FakePrivateReader(), FakeS3()
                    with self.assertRaises(AdmissionError):
                        pub.publish(store, reader, path, SHA, invalid)
                    self.assertEqual(reader.calls, [])
                    self.assertEqual(store.puts, [])

    def test_corrupt_existing_objects_prevent_all_new_uploads(self):
        with tempfile.TemporaryDirectory() as d:
            path, manifest, receipt = candidate(Path(d))
            key = manifest["files"]["index.html"]["key"]
            store = FakeS3({key: b"wrong-but-same-size-as-real"[
                :manifest["files"]["index.html"]["bytes"]].ljust(
                    manifest["files"]["index.html"]["bytes"], b"!")})
            with self.assertRaises(AdmissionError):
                pub.publish(store, FakePrivateReader(), path, SHA, receipt)
            self.assertEqual(store.puts, [])

    def test_corrupt_local_candidate_and_unsupported_godot_assets_block(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            (path / "runtime/index.pck").write_bytes(b"changed")
            with self.assertRaises(AdmissionError):
                pub.publish(FakeS3(), FakePrivateReader(), path, SHA, receipt)
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d), extra={"untrusted.js": b"x"})
            with self.assertRaises(AdmissionError):
                pub.publish(FakeS3(), FakePrivateReader(), path, SHA, receipt)

    def test_capacity_and_foreign_keys_reject_any_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            cases = [
                {ROOT + "a" * 16 + "/old": b"x" * 1},
                {"chess-studio-assets/legacy": b"x"},
                {"pawn-action/current.json": b"x"},
            ]
            for existing in cases[1:]:
                store = FakeS3(existing)
                with self.assertRaises(AdmissionError):
                    pub.publish(store, FakePrivateReader(), path, SHA, receipt)
                self.assertEqual(store.puts, [])
            _, entries = pub.entries_for(path, SHA)
            with self.assertRaises(AdmissionError):
                pub.budget({ROOT + "0" * 16 + "/old.bin": pub.MAX_BYTES}, entries)
            self.assertEqual(pub.BUCKET, "pawn-action-staging-private")

    def test_conditional_collision_same_bytes_is_allowed_only_after_SHA_readback(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            store = FakeS3()
            store.conflict = True
            with self.assertRaises(AdmissionError):
                pub.publish(store, FakePrivateReader(), path, SHA, receipt)
            self.assertEqual(len(store.puts), 1)
        with tempfile.TemporaryDirectory() as d:
            path, manifest, receipt = candidate(Path(d))
            class RacingS3(FakeS3):
                def put_object(self, **opts):
                    self.objects[opts["Key"]] = opts["Body"].read()
                    self.puts.append(opts["Key"])
                    raise Collision()
            store = RacingS3()
            pub.publish(store, FakePrivateReader(), path, SHA, receipt)
            self.assertEqual(len(store.puts), 5)
            self.assertEqual(len(store.reads), 5)

    def test_network_uncertainty_does_not_retry_or_log_secret(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            class Broken(FakeS3):
                def put_object(self, **opts):
                    self.puts.append(opts["Key"])
                    raise RuntimeError("private credential in cloud error")
            store = Broken()
            with self.assertRaises(AdmissionError) as ctx:
                pub.publish(store, FakePrivateReader(), path, SHA, receipt)
            self.assertNotIn("credential", str(ctx.exception))
            self.assertEqual(len(store.puts), 1)

    def test_inventory_pagination_bad_cursor_fails_before_put(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, receipt = candidate(Path(d))
            store = FakeS3()
            store.broken = True
            with self.assertRaises(AdmissionError):
                pub.publish(store, FakePrivateReader(), path, SHA, receipt)
            self.assertEqual(store.puts, [])

    def test_plan_and_apply_confirmation_require_no_cloud_before_source_admission(self):
        with tempfile.TemporaryDirectory() as d:
            path, manifest, receipt = candidate(Path(d))
            with patch.object(pub, "GithubReader") as github, \
                 patch.object(pub, "CloudflareReadClient") as reader, \
                 patch.object(pub, "create_client") as client, \
                 patch.object(pub, "admit") as admission:
                self.assertEqual(pub.main(["plan", "--candidate", str(path),
                    "--source-sha", SHA], {}), 0)
                self.assertEqual(pub.main(["apply", "--candidate", str(path),
                    "--source-sha", SHA], {}), 1)
                github.assert_not_called()
                reader.assert_not_called()
                client.assert_not_called()
                admission.assert_not_called()
            # Wrong or stale current-main source must not open Cloudflare.
            with patch.object(pub, "GithubReader"), \
                 patch.object(pub, "admit", side_effect=AdmissionError("not main")), \
                 patch.object(pub, "CloudflareReadClient") as reader:
                self.assertEqual(pub.main(["apply", "--candidate", str(path),
                    "--source-sha", SHA, "--confirm-immutable-upload",
                    ROOT + manifest["release"]], {"GH_TOKEN": "synthetic"}), 1)
                reader.assert_not_called()

    def test_missing_private_s3_credentials_fail_before_boto3(self):
        for env in (
            {}, {"CLOUDFLARE_ACCOUNT_ID": "a" * 32},
            {"CLOUDFLARE_ACCOUNT_ID": "a" * 32,
             "PAWN_ACTION_PRIVATE_R2_ACCESS_KEY_ID": "a"},
        ):
            with self.assertRaises(AdmissionError):
                pub.create_client(env)


if __name__ == "__main__":
    unittest.main()
