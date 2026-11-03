"""Private Pawn Action R2 owner/privacy contracts with fake Cloudflare API."""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_private_r2 as r2
from cloudflare_control_plane import InventoryError


class FakeCloudflare:
    account = "a" * 32

    def __init__(self, *, exists=True):
        self.exists = exists
        self.name = r2.BUCKET
        self.managed = {"bucketId": "b" * 32, "domain": "fixture.r2.dev",
                        "enabled": False}
        self.custom = {"domains": []}
        self.calls = []

    def get(self, path, *, allow_missing=False):
        self.calls.append((path, allow_missing))
        root = f"/accounts/{self.account}/r2/buckets/{r2.BUCKET}"
        if path == root:
            assert allow_missing is True
            return (200, {"name": self.name}) if self.exists else (404, None)
        if path == root + "/domains/managed":
            assert allow_missing is False
            return 200, self.managed
        if path == root + "/domains/custom":
            assert allow_missing is False
            return 200, self.custom
        raise AssertionError("Unexpected Cloudflare API request " + path)


class PrivateR2AdmissionTests(unittest.TestCase):
    def test_private_bucket_requires_both_visibility_surfaces_disabled(self):
        client = FakeCloudflare()
        expected = {"bucket": "owned", "r2_dev": "disabled",
                    "custom_domains": "none", "private": True}
        self.assertEqual(r2.inspect(client), expected)
        self.assertEqual(len(client.calls), 3)
        self.assertTrue(all(path.startswith("/accounts/" + client.account)
                            for path, _ in client.calls))
        self.assertFalse(any("chess-studio-assets" in path
                             for path, _ in client.calls))

    def test_absent_bucket_is_pending_not_private(self):
        client = FakeCloudflare(exists=False)
        self.assertEqual(r2.inspect(client), {
            "bucket": "absent", "r2_dev": "unchecked",
            "custom_domains": "unchecked", "private": False,
        })
        self.assertEqual(len(client.calls), 1)

    def test_managed_r2_dev_exposure_or_unknown_state_fails_closed(self):
        for value in (True, None, "false", {}, [], 1, 0):
            with self.subTest(value=value):
                client = FakeCloudflare()
                client.managed = {"enabled": value}
                with self.assertRaises(InventoryError):
                    r2.inspect(client)
                self.assertEqual(len(client.calls), 2)

    def test_custom_domain_association_forbidden_even_if_disabled(self):
        for values in (
            [{"domain": "assets.example.com", "enabled": True}],
            [{"domain": "assets.example.com", "enabled": False}],
            [{"domain": "shared.shadowops.dpdns.org", "enabled": False}],
        ):
            with self.subTest(domains=values):
                client = FakeCloudflare()
                client.custom = {"domains": values}
                with self.assertRaises(InventoryError):
                    r2.inspect(client)

    def test_incomplete_domains_response_or_mismatched_bucket_fail_closed(self):
        cases = ("wrong-name", "empty-bucket", "missing-managed",
                 "missing-custom", "unparseable-custom", "malformed-account")
        for fault in cases:
            with self.subTest(fault=fault):
                client = FakeCloudflare()
                if fault == "wrong-name":
                    client.name = "chess-studio-assets"
                elif fault == "empty-bucket":
                    client.name = ""
                elif fault == "missing-managed":
                    client.managed = None
                elif fault == "missing-custom":
                    client.custom = None
                elif fault == "unparseable-custom":
                    client.custom = {"domains": None}
                elif fault == "malformed-account":
                    client.account = "another-account"
                with self.assertRaises(InventoryError):
                    r2.inspect(client)

    def test_api_errors_never_mean_private(self):
        class Broken(FakeCloudflare):
            def get(self, path, **kwargs):
                if path.endswith("/domains/managed"):
                    raise InventoryError("Cloudflare permission denied")
                return super().get(path, **kwargs)
        with self.assertRaises(InventoryError):
            r2.inspect(Broken())

    def test_require_private_cli_fails_when_absent_without_cloud_mutation(self):
        with patch.object(r2, "CloudflareReadClient",
                          return_value=FakeCloudflare(exists=False)), \
             patch.object(sys, "argv", ["pawn_action_private_r2.py",
                                        "require-private"]), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(r2.main(), 1)

    def test_readonly_inventory_cli_reports_missing_as_pending(self):
        with patch.object(r2, "CloudflareReadClient",
                          return_value=FakeCloudflare(exists=False)), \
             patch.object(sys, "argv", ["pawn_action_private_r2.py", "inventory"]):
            self.assertEqual(r2.main(), 0)

    def test_this_module_has_no_cloud_mutators_or_public_bucket_uploads(self):
        code = Path(r2.__file__).read_text(encoding="utf-8")
        for forbidden in ("method=\"POST\"", "method=\"PUT\"", "method=\"DELETE\"",
                          "subprocess.run(", "put_object(", "create_bucket(",
                          "api.cloudflare.com/client/v4/accounts/"):
            self.assertNotIn(forbidden, code)
        self.assertNotEqual(r2.BUCKET, r2.SHARED_PUBLIC_BUCKET)
        self.assertEqual(r2.BINDING, "PAWN_ACTION_PRIVATE_R2")


if __name__ == "__main__":
    unittest.main()
