"""Offline contracts for safe, content-addressed Chronicles portrait publication."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_portrait_publish as p

SRC_SHA = "a" * 40


def stage_pack(root: Path):
    root.mkdir(exist_ok=True, parents=True)
    records = []
    manifest = {"schema": 1, "portraits": {}}
    for portrait_id in sorted(p.EXPECTED):
        # Synthetic but correctly signed media header; unit test validates
        # immutable identities, not image decoding or artistic fidelity.
        data = b"RIFF" + (26).to_bytes(4, "little") + b"WEBP" + b"VP8 " + b"\x00" * 14
        data += portrait_id.encode("ascii")
        sha = hashlib.sha256(data).hexdigest()
        key = f"portraits/{portrait_id}/awake-{sha[:16]}.webp"
        path = root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        records.append({"key": key, "size": len(data), "sha256": sha})
        manifest["portraits"][portrait_id] = {
            "awake": f"https://{p.HOST}/{key}",
        }
    (root / "sha256sums.json").write_text(json.dumps(records))
    (root / "manifest.candidate.json").write_text(json.dumps(manifest))
    return records, manifest


class FakeS3:
    def __init__(self):
        self.items = {}
        self.puts = []
        self.fail_at = None

    def list_objects_v2(self, **kwargs):
        assert kwargs["Bucket"] == "chronicles"
        assert kwargs["Prefix"] == "portraits/"
        return {"IsTruncated": False, "Contents": [
            {"Key": k, "Size": len(v)} for k, v in self.items.items()
        ]}

    def get_object(self, **kwargs):
        raw = self.items[kwargs["Key"]]
        return {
            "ContentType": "image/webp", "CacheControl": p.CACHE_CONTROL,
            "ContentLength": len(raw), "Body": io.BytesIO(raw),
        }

    def put_object(self, **kwargs):
        assert kwargs["Bucket"] == "chronicles"
        assert kwargs["IfNoneMatch"] == "*"
        assert kwargs["ContentType"] == "image/webp"
        assert kwargs["CacheControl"] == p.CACHE_CONTROL
        assert kwargs["Key"].startswith("portraits/")
        if kwargs["Key"] in self.items:
            raise AssertionError("Overwrote immutable key")
        self.puts.append(kwargs["Key"])
        self.items[kwargs["Key"]] = kwargs["Body"]


class ValidationTests(unittest.TestCase):
    def test_all_24_canonical_ids_and_hashes_have_strict_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records, manifest = stage_pack(root)
            pack = p.validate(root)
            self.assertEqual(len(pack), 24)
            self.assertEqual(set(manifest["portraits"]), p.EXPECTED)
            self.assertEqual(set(pack), {item["key"] for item in records})
            with patch.object(p, "validate_domain") as domain, \
                 patch.object(p, "create_client") as s3:
                self.assertEqual(p.main(["plan", "--stage", str(root),
                                         "--source-sha", SRC_SHA], {}), 0)
                domain.assert_not_called()
                s3.assert_not_called()

    def test_rejects_tampering_missing_extra_and_other_bucket_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records, manifest = stage_pack(root)
            key = records[0]["key"]
            path = root / key
            before = path.read_bytes()
            path.write_bytes(before + b"byte")
            with self.assertRaises(p.PublicationError):
                p.validate(root)
            path.write_bytes(before)
            (root / "portraits" / "foreign.webp").write_bytes(before)
            with self.assertRaises(p.PublicationError):
                p.validate(root)
            (root / "portraits" / "foreign.webp").unlink()
            manifest["portraits"][key.split("/")[1]]["awake"] = "https://evil.example/portrait.webp"
            (root / "manifest.candidate.json").write_text(json.dumps(manifest))
            with self.assertRaises(p.PublicationError):
                p.validate(root)

    def test_rejects_sleep_url_before_art_review_and_malformed_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records, manifest = stage_pack(root)
            portrait_id = records[0]["key"].split("/")[1]
            manifest["portraits"][portrait_id]["sleep"] = "https://example/sleep.webp"
            (root / "manifest.candidate.json").write_text(json.dumps(manifest))
            with self.assertRaises(p.PublicationError):
                p.validate(root)
            stage_pack(root)
            rows = json.loads((root / "sha256sums.json").read_text())
            rows[0]["key"] = "portraits/../other/awake-1234567890abcdef.webp"
            (root / "sha256sums.json").write_text(json.dumps(rows))
            with self.assertRaises(p.PublicationError):
                p.validate(root)

    def test_symlink_and_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows, _ = stage_pack(root)
            file = root / rows[0]["key"]
            raw = file.read_bytes()
            file.unlink()
            with self.assertRaises(p.PublicationError):
                p.validate(root)
            original = root / "not-in-stage.webp"
            original.write_bytes(raw)
            file.symlink_to(original)
            with self.assertRaises(p.PublicationError):
                p.validate(root)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        stage_pack(self.root)
        self.pack = p.validate(self.root)
        self.store = FakeS3()

    def test_immutable_publish_and_idempotent_verified_readback(self):
        with patch.object(p, "admit") as gate, patch.object(p, "public_verify") as edge:
            done = p.publish(self.store, self.pack, SRC_SHA, "token")
            self.assertEqual(done["created"], 24)
            self.assertEqual(len(self.store.puts), 24)
            self.assertEqual(gate.call_count, 2)
            self.assertEqual(edge.call_count, 24)
            again = p.publish(self.store, self.pack, SRC_SHA, "token")
            self.assertEqual(again["created"], 0)
            self.assertEqual(again["reused"], 24)
            self.assertEqual(len(self.store.puts), 24)

    def test_conflicting_existing_key_prevents_all_new_writes(self):
        key = next(iter(self.pack))
        self.store.items[key] = b"wrong"
        with patch.object(p, "admit"), patch.object(p, "public_verify") as edge:
            with self.assertRaises(p.PublicationError):
                p.publish(self.store, self.pack, SRC_SHA, "token")
            self.assertEqual(self.store.puts, [])
            edge.assert_not_called()

    def test_rejection_before_mutation_on_invalid_admission_or_budget(self):
        with patch.object(p, "admit", side_effect=p.PublicationError("not main")):
            with self.assertRaisesRegex(p.PublicationError, "not main"):
                p.publish(self.store, self.pack, SRC_SHA, "token")
            self.assertEqual(self.store.puts, [])
        with patch.object(p, "admit"), patch.object(p, "MAX_BUCKET_PREFIX", 1):
            with self.assertRaisesRegex(p.PublicationError, "budget"):
                p.publish(self.store, self.pack, SRC_SHA, "token")
            self.assertEqual(self.store.puts, [])

    def test_fails_on_malformed_inventory_and_pending_main(self):
        self.store.items["portraits/private/item.txt"] = b"not allowed"
        with patch.object(p, "admit"):
            with self.assertRaises(p.PublicationError):
                p.publish(self.store, self.pack, SRC_SHA, "token")
        with patch.object(p, "read_main_sha", return_value="b" * 40):
            with self.assertRaisesRegex(p.PublicationError, "no longer current"):
                p.admit(SRC_SHA, "token")

    def test_main_ci_must_be_green_and_read_only_token_distinct(self):
        with patch.object(p, "read_main_sha", return_value=SRC_SHA), \
             patch.object(p.source, "inspect", return_value="pending"):
            with self.assertRaisesRegex(p.PublicationError, "not all green"):
                p.admit(SRC_SHA, "token")
        invalid = {
            "CHRONICLES_R2_ACCOUNT_ID": "a" * 32,
            "CHRONICLES_R2_PORTRAIT_ACCESS_KEY_ID": "same",
            "CHRONICLES_R2_PORTRAIT_SECRET_ACCESS_KEY": "other",
            "CHRONICLES_R2_READ_TOKEN": "same",
        }
        with self.assertRaisesRegex(p.PublicationError, "must differ"):
            p.create_client(invalid)

    def test_conditional_put_conflict_requires_exact_readback(self):
        class Race(FakeS3):
            def put_object(self, **kwargs):
                self.items[kwargs["Key"]] = b"wrong-after-race"
                error = Exception("conditional conflict")
                error.response = {"Error": {"Code": "PreconditionFailed"}}
                raise error
        self.store = Race()
        with patch.object(p, "admit"), patch.object(p, "public_verify"):
            with self.assertRaises(p.PublicationError):
                p.publish(self.store, self.pack, SRC_SHA, "token")

    def test_uncertain_write_does_not_retry(self):
        class Noisy(FakeS3):
            def put_object(self, **kwargs):
                raise RuntimeError("token=secret internal failure")
        with patch.object(p, "admit"):
            with self.assertRaisesRegex(p.PublicationError, "uncertain"):
                p.publish(Noisy(), self.pack, SRC_SHA, "token")

    def test_no_publish_without_manual_confirmation(self):
        with patch.object(p, "create_client") as client, patch.object(p, "validate_domain") as domains:
            self.assertEqual(p.main(["publish", "--stage", str(self.root),
                                     "--source-sha", SRC_SHA], {}), 1)
            client.assert_not_called()
            domains.assert_not_called()


if __name__ == "__main__":
    unittest.main()
