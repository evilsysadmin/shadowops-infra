"""No-cloud contracts for source-accredited six-sheet R2 publication."""
import io
import json
import unittest
from unittest.mock import patch
import zipfile

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import football_atlas_publication as atlas
import football_delivery as delivery


def sample_pack(mutator=None):
    assets, files = [], {}
    for team in sorted(atlas.TEAMS):
        for family, rows in sorted(atlas.FAMILIES.items()):
            name = f"{team}_{family}_v1.webp"
            payload = b"RIFF" + b"12" + b"34" + b"WEBP" + name.encode()
            files[name] = payload
            assets.append({"team": team, "family": family, "file": name,
                           "rows": rows, "columns": 8, "bytes": len(payload),
                           "sha256": atlas.sha256(payload)})
    manifest = {"schema": 1, "codec": "webp-lossless",
                "cell": {"width": 128, "height": 144}, "assets": assets}
    if mutator:
        mutator(manifest, files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, raw in files.items():
            z.writestr(name, raw)
        z.writestr("atlas-manifest-v1.json", json.dumps(manifest))
    return buf.getvalue()


class AtlasPublicationContracts(unittest.TestCase):
    def test_full_source_matrix_and_hash_passes(self):
        pack = atlas.validate_pack(sample_pack())
        self.assertEqual(set(pack), atlas.EXPECTED_FILES)

    def test_tampered_payload_fails_closed(self):
        def mutate(manifest, files):
            item = manifest["assets"][0]
            files[item["file"]] += b"x"
        with self.assertRaises(delivery.DeliveryError):
            atlas.validate_pack(sample_pack(mutate))

    def test_unknown_member_rejected(self):
        def mutate(manifest, files):
            files["../unexpected.webp"] = b"RIFF1234WEBP"
        with self.assertRaises(delivery.DeliveryError):
            atlas.validate_pack(sample_pack(mutate))

    def test_layout_and_membership_not_user_selectable(self):
        def mutate(manifest, files):
            manifest["assets"][0]["rows"] = 99
        with self.assertRaises(delivery.DeliveryError):
            atlas.validate_pack(sample_pack(mutate))

    def test_only_accredited_main_sha_accepted(self):
        with patch.object(delivery, "admit", return_value=None):
            with self.assertRaises(delivery.DeliveryError):
                atlas.admitted_source("a" * 40)

    def test_public_cors_and_immutable_enforced(self):
        from email.message import Message
        class MockResponse:
            status = 200
            def __init__(self, headers):
                self.headers = Message()
                for key, value in headers.items():
                    self.headers[key] = value
            def read(self, _n): return b"RIFF0000WEBP"
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        for headers in [
            {"Access-Control-Allow-Origin": "*"},
            {"Cache-Control": "public, max-age=31536000, immutable"},
        ]:
            with patch.object(atlas.urllib.request, "urlopen", return_value=MockResponse(headers)):
                with self.assertRaises(delivery.DeliveryError):
                    atlas.public_bytes("fc_matthias_lateral_run_v1.webp")

    def test_no_write_when_free_tier_budget_denies(self):
        pack = atlas.validate_pack(sample_pack())
        with (patch.object(atlas, "admitted_source") as admit,
              patch.object(atlas.pages, "required", return_value="a" * 32),
              patch.object(delivery, "inventory", return_value={}),
              patch.object(delivery, "budget", side_effect=delivery.DeliveryError("budget")),
              patch.object(delivery, "r2_request") as mutate):
            with self.assertRaises(delivery.DeliveryError):
                atlas.publish(pack, "f" * 40)
            self.assertEqual(admit.call_count, 1)
            mutate.assert_not_called()

    def test_existing_keys_cannot_be_overwritten(self):
        pack = atlas.validate_pack(sample_pack())
        current = {atlas.PREFIX + name: len(raw) for name, raw in pack.items()}
        with (patch.object(atlas, "admitted_source"),
              patch.object(atlas.pages, "required", return_value="a" * 32),
              patch.object(delivery, "inventory", return_value=current),
              patch.object(delivery, "budget"),
              patch.object(atlas, "verify_public", side_effect=delivery.DeliveryError("mismatch")),
              patch.object(delivery, "r2_request") as mutate):
            with self.assertRaises(delivery.DeliveryError):
                atlas.publish(pack, "f" * 40)
            mutate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
