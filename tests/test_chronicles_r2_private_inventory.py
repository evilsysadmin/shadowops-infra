"""Offline contracts for the manual Chronicles R2 private inventory handoff."""
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_private_inventory as p


def domain(name=p.EXPECTED_DOMAIN, *, enabled=True):
    return {"domain": name, "enabled": enabled, "status": {"ssl": "active", "ownership": "active"}}


def api(result, *, info=None):
    response = {"success": True, "result": result}
    if info is not None:
        response["result_info"] = info
    return response


class PrivateInventoryTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.domains = api({"domains": [domain()]})
        self.pages = [api([
            {"key": "sprites/ash-goblin.webp", "size": 100},
            {"key": "music/first-verse.mp3", "size": 200},
        ], info={"is_truncated": True, "cursor": "SECRET-CURSOR"}),
        api([
            {"key": "models/source/hidden-master.blend", "size": 300},
            {"key": "unclassified/key.custom", "size": 400},
        ], info={"is_truncated": False})]

    def fetch(self, kind, cursor):
        self.calls.append((kind, cursor))
        if kind == "domains":
            return self.domains
        return self.pages[0] if cursor is None else self.pages[1]

    def test_counts_only_with_full_pagination_and_no_private_names(self):
        result = p.inspect(self.fetch)
        self.assertEqual(self.calls, [
            ("domains", None), ("objects", None), ("objects", "SECRET-CURSOR"),
        ])
        self.assertEqual(result, {
            "domain": "approved-active", "objects": "4", "bytes": "1000",
            "pages": "2", "needs_review": "2", "sprites": "1",
            "music": "1", "models": "1", "other": "1",
            "publication": "not-authorized",
        })
        for hidden in ("SECRET-CURSOR", "hidden-master", "ash-goblin", "key.custom"):
            self.assertNotIn(hidden, str(result))

    def test_domains_fail_closed_without_leaking_foreign_names(self):
        for rows in ([], [domain(enabled=False)], [domain(), domain()],
                     [domain("unexpected.example")], [{"enabled": True}]):
            with self.subTest(rows=rows):
                self.domains = api({"domains": rows})
                with self.assertRaises(p.InventoryError) as raised:
                    p.inspect(self.fetch)
                self.assertNotIn("unexpected.example", str(raised.exception))
                self.assertEqual(self.calls[-1], ("domains", None))

    def test_invalid_or_duplicated_object_rejected_without_key_log(self):
        for rows in (
            [{"key": "private/not-visible.webp", "size": -1}],
            [{"key": "private/not-visible.webp", "size": True}],
            [{"key": "private/not-visible.webp", "size": 1},
             {"key": "private/not-visible.webp", "size": 1}],
            [{"key": "/users/secret.png", "size": 0}],
        ):
            with self.subTest(rows=rows):
                self.pages = [api(rows, info={"is_truncated": False})]
                with self.assertRaises(p.InventoryError) as raised:
                    p.inspect(self.fetch)
                self.assertNotIn("not-visible", str(raised.exception))
                self.assertNotIn("/users/", str(raised.exception))

    def test_missing_broken_or_cyclic_pagination_fails_closed(self):
        for info in (None, {"is_truncated": True}, {"is_truncated": True, "cursor": ""},
                     {"is_truncated": True, "cursor": 42}):
            with self.subTest(info=info):
                self.pages = [api([], info=info)]
                with self.assertRaises(p.InventoryError):
                    p.inspect(self.fetch)
        self.pages = [api([], info={"is_truncated": True, "cursor": "replay"}),
                      api([], info={"is_truncated": True, "cursor": "replay"})]
        with self.assertRaisesRegex(p.InventoryError, "continuation"):
            p.inspect(self.fetch)

    def test_provider_access_stays_get_only_fixed_bucket_bounded(self):
        account = "a" * 32
        domains_url = p._endpoint(account, "domains", None)
        objs_url = p._endpoint(account, "objects", "opaque+cursor")
        self.assertEqual(domains_url,
            "https://api.cloudflare.com/client/v4/accounts/" + account + "/r2/buckets/chronicles/domains/custom")
        self.assertIn("/r2/buckets/chronicles/objects?", objs_url)
        self.assertIn("cursor=opaque%2Bcursor", objs_url)
        for kind, cursor in (("unknown", None), ("domains", "cursor")):
            with self.assertRaises(p.InventoryError):
                p._endpoint(account, kind, cursor)
        with self.assertRaises(p.InventoryError):
            p._endpoint("../secret", "domains", None)
        source = pathlib.Path(p.__file__).read_text()
        self.assertIn('method="GET"', source)
        self.assertIn('class _NoRedirects', source)
        self.assertNotIn('method="POST"', source)
        self.assertNotIn('method="PUT"', source)
        self.assertNotIn('method="DELETE"', source)

    def test_missing_dedicated_secrets_fails_without_network_or_values(self):
        with patch.dict(os.environ, {
            "CHRONICLES_R2_READ_TOKEN": "",
            "CHRONICLES_R2_ACCOUNT_ID": "",
        }):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(p.main(), 1)
            self.assertIn("BLOCKED", err.getvalue())
            self.assertNotIn("Authorization", err.getvalue())

    def test_never_returns_or_prints_raw_inventory_or_credentials(self):
        result = p.inspect(self.fetch)
        self.assertNotIn("SECRET-CURSOR", str(result))
        self.assertNotIn("first-verse", str(result))
        source = pathlib.Path(p.__file__).read_text()
        for unsafe in ("print(payload)", "print(rows)", "print(token)", "print(cursor)",
                       "repr(payload)", "repr(rows)", "requests.post", "subprocess.run"):
            self.assertNotIn(unsafe, source)


if __name__ == "__main__":
    unittest.main()
