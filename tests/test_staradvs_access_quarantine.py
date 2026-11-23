"""Safety tests for manual Star Adventures staging Access quarantine."""
from __future__ import annotations
import copy
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_access_quarantine as q


class FakePages:
    account = "a" * 32
    def request(self, method, path, data=None):
        assert method == "GET" and data is None
        assert path == f"/accounts/{self.account}/pages/projects/{q.PROJECT}"
        return 200, {"name": q.PROJECT, "production_branch": "main",
                     "subdomain": q.pages.TARGET, "source": None,
                     "domains": [q.pages.HOST, q.pages.TARGET]}


class FakeAccess:
    account = "a" * 32
    def __init__(self):
        self.apps = []
        self.policies = {}
        self.posts = []
        self.get_calls = []

    def get(self, path):
        self.get_calls.append(path)
        if path == f"/accounts/{self.account}/access/apps":
            return {"result": copy.deepcopy(self.apps),
                    "result_info": {"total_pages": 1, "page": 1,
                                    "count": len(self.apps), "total_count": len(self.apps)}}
        ident = path.split("/access/apps/")[1].split("/")[0]
        assert path.endswith("/policies") and ident in self.policies
        rows = self.policies[ident]
        return {"result": copy.deepcopy(rows),
                "result_info": {"total_pages": 1, "page": 1,
                                "count": len(rows), "total_count": len(rows)}}

    def post(self, path, payload):
        assert path == f"/accounts/{self.account}/access/apps"
        self.posts.append(copy.deepcopy(payload))
        ident = f"00000000-0000-4000-8000-{len(self.apps) + 1:012d}"
        self.apps.append({"id": ident, "type": "self_hosted",
                          "destinations": copy.deepcopy(payload["destinations"])})
        self.policies[ident] = copy.deepcopy(payload["policies"])
        return {"id": ident}


class Tests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAccess()
        self.pages = FakePages()
        owner = patch.object(q.pages, "inspect", return_value=(
            "z" * 32, {"dns": "owned", "project": "owned", "domain": "owned"}))
        owner.start()
        self.addCleanup(owner.stop)

    def test_creates_exact_three_individual_policies_then_idempotent(self):
        self.assertEqual(set(q.plan(self.fake, self.pages).values()), {"missing"})
        count, states = q.apply(self.fake, self.pages, "operator@private.invalid",
                                confirmation=q.CONFIRM)
        self.assertEqual(count, 3)
        self.assertEqual(set(states.values()), {"restricted-policy-candidate"})
        self.assertEqual(len(self.fake.posts), 3)
        self.assertEqual([item["destinations"][0]["uri"] for item in self.fake.posts],
                         [host for _, host in q.SCOPES])
        for item in self.fake.posts:
            self.assertEqual(item["type"], "self_hosted")
            self.assertEqual(len(item["destinations"]), 1)
            self.assertEqual(item["policies"][0]["decision"], "allow")
            self.assertEqual(item["policies"][0]["include"],
                             [{"email": {"email": "operator@private.invalid"}}])
            self.assertNotIn("bypass", str(item).lower())
        count2, _ = q.apply(self.fake, self.pages, "operator@private.invalid",
                            confirmation=q.CONFIRM)
        self.assertEqual(count2, 0)
        self.assertEqual(len(self.fake.posts), 3)

    def test_no_confirmation_or_broad_identity_cannot_write(self):
        for email, confirm in (
            ("operator@private.invalid", ""), ("*@example.com", q.CONFIRM),
            ("", q.CONFIRM), ("foo@example.com,bar@example.com", q.CONFIRM),
        ):
            with self.subTest(email=email):
                with self.assertRaises(q.QuarantineError):
                    q.apply(self.fake, self.pages, email, confirmation=confirm)
        self.assertEqual(len(self.fake.posts), 0)

    def test_reject_cross_game_wildcard_overlap(self):
        self.fake.apps.append({
            "id": "00000000-0000-4000-8000-000000000001",
            "type": "self_hosted",
            "destinations": [{"type": "public", "uri": "*.pages.dev"}],
        })
        with self.assertRaises(q.QuarantineError):
            q.apply(self.fake, self.pages, "operator@private.invalid",
                    confirmation=q.CONFIRM)
        self.assertEqual(self.fake.posts, [])

    def test_resume_after_partial_apply_without_touching_existing_app(self):
        self.fake.post(f"/accounts/{self.fake.account}/access/apps",
                       q.payload_for(*q.SCOPES[0], "operator@private.invalid"))
        self.fake.posts.clear()
        count, states = q.apply(self.fake, self.pages, "operator@private.invalid",
                                confirmation=q.CONFIRM)
        self.assertEqual(count, 2)
        self.assertEqual(len(self.fake.posts), 2)
        self.assertEqual(set(states.values()), {"restricted-policy-candidate"})

    def test_foreign_owner_or_accounts_rejected(self):
        self.pages.account = "b" * 32
        with self.assertRaises(q.QuarantineError):
            q.plan(self.fake, self.pages)
        self.pages.account = "a" * 32
        with patch.object(q.pages, "inspect", return_value=(
            "z" * 32, {"dns": "owned", "domain": "missing", "project": "owned"})):
            with self.assertRaises(q.QuarantineError):
                q.plan(self.fake, self.pages)
        self.assertEqual(self.fake.posts, [])

    def test_forbid_unrelated_http_mutation_without_network(self):
        with patch("urllib.request.build_opener", side_effect=AssertionError("NETWORK")):
            writer = q.AccessWriter({"CLOUDFLARE_ACCOUNT_ID": "a" * 32,
                                     "CLOUDFLARE_ACCESS_WRITE_TOKEN": "unit-test"})
            with self.assertRaises(q.QuarantineError):
                writer.post("/accounts/" + "a" * 32 + "/dns_records", {"type": "self_hosted"})
        with self.assertRaises(q.QuarantineError):
            q.payload_for("chronicles-production", "chronicles-production.pages.dev",
                          "operator@private.invalid")

    def test_workflow_never_writes_unattended(self):
        flow = (ROOT / ".github/workflows/staradvs-access-quarantine.yml").read_text()
        for text in ("workflow_dispatch:", "STARADVS_QUARANTINE_ACCESS",
                     "environment: staging", "CLOUDFLARE_ACCESS_WRITE_TOKEN",
                     "staradvs_access_quarantine.py apply",
                     "github.ref == 'refs/heads/main'",
                     "github.event_name == 'workflow_dispatch'",
                     "gh api repos/evilsysadmin/shadowops-infra/commits/main"):
            self.assertIn(text, flow)
        self.assertNotIn("contents: write", flow)
        self.assertNotIn("CLOUDFLARE_ACCESS_READ_TOKEN", flow)


if __name__ == "__main__":
    unittest.main()
