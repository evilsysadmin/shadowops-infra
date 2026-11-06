"""Synthetic, offline evidence parity tests; never contact Cloudflare or GitHub."""
from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_handoff_parity as p


OPERATOR = "\n".join([
    "CHRONICLES_R2_OPERATOR_INVENTORY objects 4",
    "CHRONICLES_R2_OPERATOR_INVENTORY bytes 1000",
    "CHRONICLES_R2_OPERATOR_INVENTORY prefix_counts models:1,music:1,sprites:1,secret-family:1",
    "CHRONICLES_R2_OPERATOR_INVENTORY needs_review 1",
    "CHRONICLES_R2_OPERATOR_INVENTORY public_readiness manual-review-required",
    "CHRONICLES_R2_OPERATOR_PROBE domain assets.chronicles.shadowops.dpdns.org",
    "CHRONICLES_R2_OPERATOR_PROBE asset ok",
    "CHRONICLES_R2_OPERATOR_PROBE cors ok",
    "CHRONICLES_R2_OPERATOR_PROBE cache mutable-safe",
    "CHRONICLES_R2_OPERATOR_PROBE cache_header public, max-age=14400",
    "CHRONICLES_R2_OPERATOR_PROBE url https://assets.chronicles.shadowops.dpdns.org/sprites/ash-goblin.webp",
    "CHRONICLES_R2_IMMUTABLE_EDGE asset ok",
    "CHRONICLES_R2_IMMUTABLE_EDGE browser_cache immutable-one-year",
    "CHRONICLES_R2_IMMUTABLE_EDGE public_sha256 " + p.IMMUTABLE_SHA256,
    "CHRONICLES_R2_IMMUTABLE_EDGE public_bytes " + str(p.IMMUTABLE_SIZE),
    "CHRONICLES_R2_IMMUTABLE_EDGE url https://assets.chronicles.shadowops.dpdns.org/sprites/ash-goblin.webp",
]) + "\n"

PRIVATE = "\n".join([
    "CHRONICLES_R2_INVENTORY domain=approved-active",
    "CHRONICLES_R2_INVENTORY objects=4",
    "CHRONICLES_R2_INVENTORY bytes=1000",
    "CHRONICLES_R2_INVENTORY needs_review=1",
    "CHRONICLES_R2_INVENTORY pages=2",
    "CHRONICLES_R2_INVENTORY sprites=1",
    "CHRONICLES_R2_INVENTORY music=1",
    "CHRONICLES_R2_INVENTORY models=1",
    "CHRONICLES_R2_INVENTORY other=1",
    "CHRONICLES_R2_INVENTORY publication=not-authorized",
]) + "\n"

EDGE = "\n".join([
    "CHRONICLES_R2_EDGE_OK edge=ok",
    "CHRONICLES_R2_EDGE_OK bytes=" + str(p.IMMUTABLE_SIZE),
    "CHRONICLES_R2_EDGE_OK immutable_sha256=" + p.IMMUTABLE_SHA256,
]) + "\n"


class R2HandoffParityTests(unittest.TestCase):
    def test_matching_receipts_require_all_three_sides(self):
        result = p.verify(OPERATOR, PRIVATE, EDGE)
        self.assertEqual(result["status"], "matching-manual-receipts")
        self.assertEqual(result["objects"], "4")
        self.assertEqual(result["bytes"], "1000")
        self.assertEqual(result["cutover"], "not-authorized")
        for hidden in ("secret-family", "ash-goblin", "cursor", "https://"):
            self.assertNotIn(hidden, str(result))

    def test_legacy_unknown_family_maps_to_other_without_exposing_name(self):
        old = OPERATOR.replace("secret-family:1", "classified-private-source:1")
        result = p.verify(old, PRIVATE, EDGE)
        self.assertEqual(result["objects"], "4")
        self.assertNotIn("classified-private-source", str(result))

    def test_inventory_mismatch_blocks_objects_bytes_review_and_family(self):
        cases = (
            ("objects=4", "objects=5", "objects"),
            ("bytes=1000", "bytes=1001", "bytes"),
            ("needs_review=1", "needs_review=2", "needs_review"),
            ("sprites=1", "sprites=0", "count"),
        )
        for previous, updated, label in cases:
            with self.subTest(field=label):
                with self.assertRaises(p.ParityError):
                    p.verify(OPERATOR, PRIVATE.replace(previous, updated), EDGE)

    def test_invalid_public_or_legacy_evidence_blocks(self):
        bad = (
            (OPERATOR.replace("domain assets.chronicles.shadowops.dpdns.org", "domain wrong.example"), PRIVATE, EDGE),
            (OPERATOR.replace("cache mutable-safe", "cache unsafe-ttl"), PRIVATE, EDGE),
            (OPERATOR.replace("public_readiness manual-review-required", "public_readiness public"), PRIVATE, EDGE),
            (OPERATOR.replace("asset ok", "asset bad-mime"), PRIVATE, EDGE),
            (OPERATOR, PRIVATE.replace("publication=not-authorized", "publication=enabled"), EDGE),
            (OPERATOR, PRIVATE.replace("domain=approved-active", "domain=wrong"), EDGE),
            (OPERATOR, PRIVATE, EDGE.replace("edge=ok", "edge=failed")),
            (OPERATOR, PRIVATE, EDGE.replace("immutable_sha256=" + p.IMMUTABLE_SHA256, "immutable_sha256=" + "0" * 64)),
        )
        for old, private, edge in bad:
            with self.subTest(case=bad.index((old, private, edge))):
                with self.assertRaises(p.ParityError):
                    p.verify(old, private, edge)

    def test_missing_duplicate_blocked_and_truncated_receipts_rejected(self):
        for old, private, edge in (
            (OPERATOR.replace("CHRONICLES_R2_OPERATOR_INVENTORY objects 4\n", ""), PRIVATE, EDGE),
            (OPERATOR + "CHRONICLES_R2_OPERATOR_PROBE domain spoofed\n", PRIVATE, EDGE),
            (OPERATOR, PRIVATE + "CHRONICLES_R2_INVENTORY bytes=1000\n", EDGE),
            (OPERATOR, PRIVATE, ""),
            (OPERATOR + "CHRONICLES_R2_OPERATOR_PROBE_BLOCKED CloudflareError\n", PRIVATE, EDGE),
            (OPERATOR, PRIVATE + "CHRONICLES_R2_INVENTORY_BLOCKED Authorization\n", EDGE),
            (OPERATOR, PRIVATE.replace("pages=2", "pages=101"), EDGE),
            (OPERATOR, PRIVATE.replace("bytes=1000", "bytes=-1000"), EDGE),
        ):
            with self.assertRaises(p.ParityError):
                p.verify(old, private, edge)

    def test_legacy_prefix_breakdown_must_be_exact(self):
        for value in ("none", "sprites:4", "music:1,music:3", "music:abc", "music:1,"):
            old = OPERATOR.replace("models:1,music:1,sprites:1,secret-family:1", value)
            with self.subTest(value=value):
                with self.assertRaises(p.ParityError):
                    p.verify(old, PRIVATE, EDGE)

    def test_cli_does_not_print_raw_receipts_or_allow_cutover(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for name, value in (("legacy.log", OPERATOR), ("private.log", PRIVATE), ("edge.log", EDGE)):
                file = pathlib.Path(tmp) / name
                file.write_text(value, encoding="utf-8")
                files.append(file)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = p.main(["--operator", str(files[0]), "--private", str(files[1]), "--edge", str(files[2])])
            self.assertEqual(code, 0, stderr.getvalue())
            self.assertIn("CHRONICLES_R2_HANDOFF_PARITY", stdout.getvalue())
            self.assertIn("cutover=not-authorized", stdout.getvalue())
            self.assertNotIn("secret-family", stdout.getvalue())
            files[1].write_text(PRIVATE.replace("bytes=1000", "bytes=42"), encoding="utf-8")
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = p.main(["--operator", str(files[0]), "--private", str(files[1]), "--edge", str(files[2])])
            self.assertEqual(code, 1)
            self.assertIn("CHRONICLES_R2_HANDOFF_BLOCKED", stderr.getvalue())
            self.assertNotIn("secret-family", stderr.getvalue())

    def test_oversized_input_is_rejected(self):
        with self.assertRaisesRegex(p.ParityError, "bounded input"):
            p.verify(OPERATOR + "x" * (p.MAX_INPUT_BYTES + 1), PRIVATE, EDGE)


if __name__ == "__main__":
    unittest.main()
