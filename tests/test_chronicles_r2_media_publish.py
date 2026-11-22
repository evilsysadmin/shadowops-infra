"""Offline safety contracts for controlled Chronicles media-only R2 copy."""
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
import chronicles_r2_media_publish as p

SOURCE_SHA = "a" * 40


def build_manifest(path):
    doc = {"version": 1, "baseUrl": "https://" + p.LEGACY_HOST, "assets": {}}
    for logical, asset in p.PINS_BY_ID.items():
        doc["assets"][logical] = {
            "bytes": asset.size, "contentType": asset.mime, "key": asset.key,
            "sha256": asset.sha256, "url": "https://" + p.LEGACY_HOST + "/" + asset.key,
        }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return doc


class FakeR2:
    def __init__(self, pack):
        self.pack = pack
        self.data = {}
        self.puts = []
        self.truncated = False

    def list_objects_v2(self, **params):
        assert params == {"Bucket": "chronicles", "Prefix": "chronicles/", "MaxKeys": 1000}
        return {"IsTruncated": self.truncated, "Contents": [
            {"Key": k, "Size": len(v)} for k, v in self.data.items()
        ]}

    def get_object(self, **params):
        asset = next(a for a in self.pack if a.key == params["Key"])
        raw = self.data[asset.key]
        return {"ContentLength": len(raw), "ContentType": asset.mime,
                "CacheControl": p.cache(asset), "Body": io.BytesIO(raw)}

    def put_object(self, **params):
        assert params["Bucket"] == p.BUCKET
        assert params["IfNoneMatch"] == "*"
        asset = next(a for a in self.pack if a.key == params["Key"])
        assert params["ContentType"] == asset.mime
        assert params["CacheControl"] == p.cache(asset)
        assert params["ContentLength"] == asset.size
        if params["Key"] in self.data:
            raise AssertionError("Overwrote existing key")
        self.puts.append(params["Key"])
        self.data[params["Key"]] = params["Body"]


class CopyContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = Path(self.temp.name) / "manifest.json"
        build_manifest(self.manifest)
        self.pack = {
            a: (a.name.encode() * (a.size // len(a.name) + 1))[:a.size]
            for a in p.media.PINS
        }
        self.s3 = FakeR2(self.pack)

    def test_exact_four_manifest_pins_and_no_other_games(self):
        self.assertEqual(p.validate_manifest(self.manifest), p.media.PINS)
        self.assertEqual(set(p.PINS_BY_ID), {
            "chronicles.music.firstVerse", "chronicles.music.secondVerse",
            "chronicles.tactics.party.master", "chronicles.tactics.party.runtime",
        })
        for logical in p.PINS_BY_ID:
            doc = build_manifest(self.manifest)
            doc["assets"][logical]["sha256"] = "0" * 64
            self.manifest.write_text(json.dumps(doc))
            with self.assertRaisesRegex(p.PublicationError, "pin or URL"):
                p.validate_manifest(self.manifest)
        doc = build_manifest(self.manifest)
        doc["assets"]["warRoom.v4.runtime"] = {}
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaises(p.PublicationError):
            p.validate_manifest(self.manifest)

    def test_source_media_reads_use_encoded_fixed_https_host_and_pin(self):
        self.assertIn("%20", p.url(p.LEGACY_HOST, p.media.PINS[0].key))
        self.assertEqual(p.url(p.LEGACY_HOST, p.media.PINS[0].key).split("/")[2],
                         p.LEGACY_HOST)
        with self.assertRaisesRegex(p.PublicationError, "hash/size"):
            p.prepare(fetch=lambda url, size: b"not original media")

    def test_read_only_plan_never_requests_s3_or_cloudflare_credentials(self):
        with patch.object(p, "prepare", return_value=self.pack), \
             patch.object(p, "create_client") as client, \
             patch.object(p, "verify_domain") as domain, \
             patch.object(p, "admit") as admission:
            self.assertEqual(p.main(["plan", "--manifest", str(self.manifest),
                                     "--source-sha", SOURCE_SHA], {}), 0)
            client.assert_not_called()
            domain.assert_not_called()
            admission.assert_not_called()

    def test_publish_requires_explicit_confirmation_before_s3(self):
        with patch.object(p, "prepare", return_value=self.pack), \
             patch.object(p, "create_client") as client, \
             patch.object(p, "verify_domain") as domain:
            self.assertEqual(p.main(["publish", "--manifest", str(self.manifest),
                                     "--source-sha", SOURCE_SHA], {}), 1)
            client.assert_not_called()
            domain.assert_not_called()

    def test_idempotent_reuse_requires_proven_matching_bytes(self):
        self.s3.data = {a.key: raw for a, raw in self.pack.items()}
        with patch.object(p, "admit") as gate, patch.object(p, "public_verify") as edge:
            result = p.publish(self.s3, self.pack, SOURCE_SHA, "token")
            self.assertEqual(result["created"], 0)
            self.assertEqual(result["reused"], 4)
            self.assertEqual(gate.call_count, 2)
            self.assertEqual(edge.call_count, 4)
            self.assertEqual(self.s3.puts, [])

    def test_conditional_creation_only_after_all_preflights(self):
        with patch.object(p, "admit") as gate, patch.object(p, "public_verify") as edge:
            result = p.publish(self.s3, self.pack, SOURCE_SHA, "token")
            self.assertEqual(result["created"], 4)
            self.assertEqual(len(self.s3.puts), 4)
            self.assertEqual(gate.call_count, 2)
            self.assertEqual(edge.call_count, 4)
            self.assertEqual(set(self.s3.data), {a.key for a in self.pack})
        receipt = p.candidate(self.pack)
        self.assertEqual(receipt["activation"], "manual-pr-required")
        self.assertEqual(set(receipt["assets"]), set(p.PINS_BY_ID))
        self.assertTrue(all("assets.chronicles.shadowops.dpdns.org" in row["url"]
                            for row in receipt["assets"].values()))

    def test_conflicting_existing_bytes_block_all_new_writes(self):
        asset = next(iter(self.pack))
        self.s3.data[asset.key] = b"x" * asset.size
        with patch.object(p, "admit"), patch.object(p, "public_verify") as edge:
            with self.assertRaisesRegex(p.PublicationError, "hash/size"):
                p.publish(self.s3, self.pack, SOURCE_SHA, "token")
            edge.assert_not_called()
            self.assertEqual(self.s3.puts, [])

    def test_unexpected_prefix_or_truncated_listing_fails_closed(self):
        self.s3.data["chronicles/private.txt"] = b"x"
        with self.assertRaisesRegex(p.PublicationError, "Unexpected"):
            p.inventory(self.s3)
        self.s3.data.clear()
        self.s3.truncated = True
        with self.assertRaisesRegex(p.PublicationError, "incomplete"):
            p.inventory(self.s3)

    def test_source_admission_rejects_stale_or_pending_main(self):
        payload = json.dumps({"sha": SOURCE_SHA}).encode()
        with patch.object(p, "fixed_get", return_value=payload), \
             patch.object(p.source, "inspect", return_value="pending"):
            with self.assertRaisesRegex(p.PublicationError, "not green"):
                p.admit(SOURCE_SHA, "token")
        payload = json.dumps({"sha": "b" * 40}).encode()
        with patch.object(p, "fixed_get", return_value=payload), \
             patch.object(p.source, "inspect") as inspect:
            with self.assertRaisesRegex(p.PublicationError, "SHA changed"):
                p.admit(SOURCE_SHA, "token")
            inspect.assert_not_called()

    def test_ambiguous_s3_write_fails_without_retries(self):
        class Uncertain(FakeR2):
            def put_object(self, **params):
                raise RuntimeError("secret-key-should-not-be-in-error")
        with patch.object(p, "admit"):
            with self.assertRaisesRegex(p.PublicationError, "Uncertain conditional"):
                p.publish(Uncertain(self.pack), self.pack, SOURCE_SHA, "token")

    def test_race_collision_requires_byte_identical_r2_readback(self):
        class Race(FakeR2):
            def put_object(self, **params):
                self.data[params["Key"]] = b"wrong"
                error = RuntimeError("collision")
                error.response = {"Error": {"Code": "PreconditionFailed"}}
                raise error
        with patch.object(p, "admit"), patch.object(p, "public_verify"):
            with self.assertRaises(p.PublicationError):
                p.publish(Race(self.pack), self.pack, SOURCE_SHA, "token")

    def test_s3_keys_are_dedicated_and_no_destructive_operations(self):
        code = Path(p.__file__).read_text(encoding="utf-8")
        self.assertIn('IfNoneMatch="*"', code)
        self.assertIn('"total_max_attempts": 1', code)
        self.assertNotIn("delete_object(", code)
        self.assertNotIn("copy_object(", code)
        self.assertNotIn("CHRONICLES_R2_PORTRAIT_ACCESS_KEY_ID", code)
        self.assertEqual(p.PREFIX, "chronicles/")
        self.assertEqual(p.BUCKET, "chronicles")


if __name__ == "__main__":
    unittest.main()
