"""Pawn Action staging DNS/Pages ownership tests: offline and mutation-free."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_pages as pawn
from cloudflare_control_plane import InventoryError


class FakeCloudflare:
    account = "a" * 32

    def __init__(self):
        self.zones = [{"name": pawn.ZONE, "id": "z" * 32}]
        self.project = None
        self.domain = None
        self.dns = []
        self.calls = []

    def get(self, path, *, allow_missing=False):
        self.calls.append(("GET", path, allow_missing))
        if path.startswith("/zones?"):
            return 200, self.zones
        if "/dns_records?" in path:
            return 200, self.dns
        if path.endswith("/domains/" + pawn.HOST):
            return (200, self.domain) if self.domain is not None else (404, None)
        if path.endswith("/pages/projects/" + pawn.PROJECT):
            return (200, self.project) if self.project is not None else (404, None)
        raise AssertionError("Unexpected Cloudflare endpoint: " + path)


def owned():
    client = FakeCloudflare()
    client.project = {
        "name": pawn.PROJECT, "production_branch": "main", "source": None,
        "subdomain": pawn.PROJECT + "-abc.pages.dev",
        "domains": [pawn.HOST, pawn.PROJECT + "-abc.pages.dev"],
    }
    client.domain = {"name": pawn.HOST, "status": "active"}
    client.dns = [{
        "name": pawn.HOST, "type": "CNAME", "proxied": True,
        "content": pawn.PROJECT + "-abc.pages.dev",
    }]
    return client


class PawnActionStagingOwnershipTests(unittest.TestCase):
    def test_hostname_and_zone_are_exact_and_not_football_or_legacy_chess(self):
        pawn.self_test()
        self.assertEqual(pawn.HOST, "staging.pawnaction.shadowops.dpdns.org")
        self.assertEqual(pawn.ZONE, "shadowops.dpdns.org")
        self.assertNotIn("shadwops.dpns.org", pawn.HOST)

    def test_absent_project_and_dns_are_safe_pending_state(self):
        client = FakeCloudflare()
        self.assertEqual(pawn.inspect(client), {
            "host": pawn.HOST, "pages": "absent",
            "dns": "absent", "custom_domain": "absent",
        })
        self.assertTrue(all(method == "GET" for method, _, _ in client.calls))

    def test_exact_owned_pages_dns_and_domain_are_accepted(self):
        client = owned()
        result = pawn.inspect(client)
        self.assertEqual((result["pages"], result["dns"], result["custom_domain"]),
                         ("owned", "owned", "active"))
        self.assertEqual(len(client.calls), 4)

    def test_unprovisioned_domain_is_pending_if_dns_absent(self):
        client = owned()
        client.domain = None
        client.dns = []
        self.assertEqual(pawn.inspect(client)["custom_domain"], "absent")

    def test_foreign_or_orphan_dns_is_always_blocked(self):
        for fault in ("orphan", "ip", "unproxied", "wrong_target", "duplicate",
                      "no_custom_domain"):
            with self.subTest(fault=fault):
                client = owned()
                if fault == "orphan":
                    client.project = None
                elif fault == "ip":
                    client.dns[0]["type"] = "A"
                elif fault == "unproxied":
                    client.dns[0]["proxied"] = False
                elif fault == "wrong_target":
                    client.dns[0]["content"] = "football-staging.pages.dev"
                elif fault == "duplicate":
                    client.dns.append(dict(client.dns[0]))
                elif fault == "no_custom_domain":
                    client.domain = None
                with self.assertRaises(InventoryError):
                    pawn.inspect(client)

    def test_foreign_pages_project_or_domains_cannot_be_adopted(self):
        for fault in ("name", "branch", "source", "subdomain", "foreign_domain",
                      "domain_name", "domain_status"):
            with self.subTest(fault=fault):
                client = owned()
                if fault == "name":
                    client.project["name"] = "football-staging"
                elif fault == "branch":
                    client.project["production_branch"] = "develop"
                elif fault == "source":
                    client.project["source"] = {"type": "github"}
                elif fault == "subdomain":
                    client.project["subdomain"] = "football-staging.pages.dev"
                elif fault == "foreign_domain":
                    client.project["domains"].append("staging.staradvs.shadowops.dpdns.org")
                elif fault == "domain_name":
                    client.domain["name"] = "staging.football.shadowops.dpdns.org"
                elif fault == "domain_status":
                    client.domain["status"] = "blocked"
                with self.assertRaises(InventoryError):
                    pawn.inspect(client)

    def test_missing_or_ambiguous_zone_is_not_assumed_owned(self):
        for zones in ([], [
            {"name": pawn.ZONE, "id": "one"},
            {"name": pawn.ZONE, "id": "two"},
        ], None):
            with self.subTest(zones=zones):
                client = FakeCloudflare()
                client.zones = zones
                with self.assertRaises(InventoryError):
                    pawn.inspect(client)


if __name__ == "__main__":
    unittest.main()
