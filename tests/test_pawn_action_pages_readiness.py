"""Read-only Pages first-release and deny-only staging phase contracts."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_pages_readiness as mod
from cloudflare_control_plane import InventoryError

ACCOUNT = "a" * 32
ROOT = "/accounts/" + ACCOUNT + "/pages/projects/pawn-action-staging"
OWNED = {"pages": "owned", "dns": "absent", "custom_domain": "absent"}
MISSING = {"pages": "absent", "dns": "absent", "custom_domain": "absent"}


class Reader:
    account = ACCOUNT

    def __init__(self, history=None, latest=None, canonical=None):
        self.history = [] if history is None else history
        self.latest, self.canonical = latest, canonical
        self.calls = []

    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        if path == ROOT + "/deployments?per_page=2&page=1":
            return 200, self.history
        if path == ROOT + "/deployments?per_page=1&page=1":
            return 200, self.history[:1]
        if path == ROOT:
            return 200, {
                "name": "pawn-action-staging", "source": None,
                "production_branch": "main", "subdomain": "pawn-action-staging.pages.dev",
                "domains": ["pawn-action-staging.pages.dev"],
                "latest_deployment": self.latest, "canonical_deployment": self.canonical,
            }
        raise AssertionError("Unexpected Cloudflare API read: " + path)


class ReadinessTests(unittest.TestCase):
    def test_missing_is_read_only_and_never_probes(self):
        r = Reader()
        with patch.object(mod, "inspect_pages", return_value=MISSING):
            result = mod.inspect(r, lambda _: self.fail("must not probe missing project"))
        self.assertEqual(result["state"], "not_reserved")
        self.assertEqual(result["cloudflareWrites"], 0)
        self.assertFalse(result["gameReady"])
        self.assertEqual(r.calls, [])

    def test_empty_requires_two_consistent_inventory_sources(self):
        r = Reader()
        with patch.object(mod, "inspect_pages", return_value=OWNED):
            result = mod.inspect(r, lambda _: self.fail("must not probe empty project"))
        self.assertEqual(result["state"], "reserved_empty")
        self.assertEqual(r.calls, [
            ROOT + "/deployments?per_page=2&page=1",
            ROOT, ROOT + "/deployments?per_page=1&page=1"])
        for latest, canonical in (({"id": "existing"}, None),
                                  (None, {"id": "existing"})):
            r = Reader(latest=latest, canonical=canonical)
            with patch.object(mod, "inspect_pages", return_value=OWNED):
                with self.assertRaises(mod.ProvisionError):
                    mod.inspect(r)

    def test_locked_only_after_exact_production_identity_and_alias_probe(self):
        one = {"id": "first", "environment": "production"}
        r = Reader([one], latest={"id": "first"}, canonical={"id": "first"})
        seen = []
        def check(reader):
            seen.append(reader)
            return {"locked": True, "gameReady": False,
                    "alias": "pawn-action-staging.pages.dev", "checks": 36}
        with patch.object(mod, "inspect_pages", return_value=OWNED):
            result = mod.inspect(r, check)
        self.assertEqual(result["state"], "locked_alias_verified")
        self.assertEqual(result["alias"], "pawn-action-staging.pages.dev")
        self.assertIs(seen[0], r)
        self.assertFalse(result["gameReady"])
        self.assertEqual(result["cloudflareWrites"], 0)

    def test_preview_extra_history_and_unmatched_metadata_fail_closed(self):
        one = {"id": "first", "environment": "production"}
        cases = [
            Reader([one, {"id": "preview", "environment": "preview"}],
                   latest={"id": "first"}, canonical={"id": "first"}),
            Reader([{"id": "preview", "environment": "preview"}],
                   latest={"id": "preview"}),
            Reader([{"id": "first"}], latest={"id": "first"}, canonical={"id": "first"}),
            Reader([one], latest={"id": "other"}, canonical={"id": "first"}),
            Reader([one], latest={"id": "first"}, canonical=None),
            Reader({"invalid": "shape"}),
        ]
        for r in cases:
            with self.subTest(history=r.history), patch.object(mod, "inspect_pages", return_value=OWNED):
                with self.assertRaises(mod.ReadinessError):
                    mod.inspect(r, lambda _: self.fail("must not probe untrusted deployment"))
        r = Reader([one], latest={"id": "first"}, canonical={"id": "first"})
        with patch.object(mod, "inspect_pages", return_value=OWNED):
            with self.assertRaises(mod.ReadinessError):
                mod.inspect(r, lambda _: {"locked": False, "gameReady": False})

    def test_dns_or_foreign_project_never_adopted(self):
        for state in (
            {"pages": "owned", "dns": "owned", "custom_domain": "active"},
            {"pages": "owned", "dns": "absent", "custom_domain": "pending"},
            {"pages": "foreign", "dns": "absent", "custom_domain": "absent"},
            {"pages": "absent", "dns": "owned", "custom_domain": "absent"},
        ):
            r = Reader()
            with self.subTest(state=state), patch.object(mod, "inspect_pages", return_value=state):
                with self.assertRaises(mod.ReadinessError):
                    mod.inspect(r)
                self.assertEqual(r.calls, [])

    def test_workflow_inspection_is_manual_staging_read_only(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/pawn-action-pages-create.yml").read_text()
        part = workflow.split("  inspect:\n", 1)[1].split("  reserve:\n", 1)[0]
        self.assertIn("inputs.operation == 'inspect'", part)
        self.assertIn("github.ref == 'refs/heads/main'", part)
        self.assertIn("name: staging", part)
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", part)
        self.assertNotIn("PAWN_ACTION_PAGES_PROVISION_TOKEN", part)
        self.assertNotIn("wrangler", part.lower())
        self.assertIn("python3 scripts/pawn_action_pages_readiness.py inspect", part)
        with patch.object(mod, "CloudflareReadClient", side_effect=InventoryError("no token")):
            self.assertEqual(mod.main(["inspect"]), 1)
        self.assertEqual(mod.main(["reserve"]), 2)


if __name__ == "__main__":
    unittest.main()
