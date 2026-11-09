import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_pages_provision as provision
import snooker_pages_readiness as readiness

ACCOUNT = "a" * 32
PROJECT = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
ZONE = "/zones?" + urlencode({"name": readiness.ZONE, "account.id": ACCOUNT})
DNS = "/zones/z-one/dns_records?" + urlencode({"name": readiness.HOST, "per_page": 100})

class Fake:
    account = ACCOUNT
    def __init__(self, *, foreign=False, orphan=False, bad_flags=False, ignore_patch=False):
        self.project = {"name": readiness.PROJECT, "production_branch": "main",
                        "source": {"type": "github"} if foreign else None,
                        "domains": [], "subdomain": "snooker-staging.pages.dev",
                        "deployment_configs": {
                            "production": {"compatibility_flags": ["global_fetch_private_origin"] if bad_flags else []},
                            "preview": {"compatibility_flags": []},
                        }} if foreign or bad_flags else None
        self.orphan = orphan
        self.ignore_patch = ignore_patch
        self.writes = []

    def get(self, path):
        if path == ZONE:
            return [{"name": readiness.ZONE, "id": "z-one"}]
        if path == PROJECT:
            return self.project
        if path == PROJECT + "/domains/" + readiness.HOST:
            return None
        if path == DNS:
            return [{"name": readiness.HOST, "type": "CNAME",
                     "proxied": True, "content": "foreign.pages.dev"}] if self.orphan else []
        raise AssertionError("Unexpected Cloudflare GET: " + path)

    def write(self, method, path, data):
        self.writes.append((method, path, data))
        if method == "POST":
            self.project = {"name": readiness.PROJECT, "production_branch": "main",
                            "source": None, "domains": [], "subdomain": "snooker-staging.pages.dev",
                            "deployment_configs": {"production": {}, "preview": {}}}
            return self.project
        if not self.ignore_patch:
            self.project["deployment_configs"] = data["deployment_configs"]
        return self.project

class ProvisionTests(unittest.TestCase):
    def test_empty_inventory_creates_only_project_and_two_private_modes(self):
        cloud = Fake()
        receipt = provision.ensure(cloud)
        self.assertEqual(receipt["deployed"], "false")
        self.assertEqual(receipt["domain"], "absent")
        self.assertEqual(receipt["dns"], "absent")
        self.assertEqual([item[0] for item in cloud.writes], ["POST", "PATCH"])
        self.assertNotIn("/domains", str(cloud.writes))
        for key in ("production", "preview"):
            self.assertIs(cloud.project["deployment_configs"][key]["fail_open"], False)
            self.assertIn("global_fetch_strictly_public",
                          cloud.project["deployment_configs"][key]["compatibility_flags"])

    def test_idempotent_project_does_not_get_created_again(self):
        cloud = Fake()
        provision.ensure(cloud)
        cloud.writes.clear()
        provision.ensure(cloud)
        self.assertEqual([w[0] for w in cloud.writes], ["PATCH"])

    def test_foreign_project_and_orphan_dns_rejected_before_any_write(self):
        for cloud in (Fake(foreign=True), Fake(orphan=True), Fake(bad_flags=True)):
            with self.subTest(cloud=cloud.__dict__), self.assertRaises(
                    (provision.ProvisionError, readiness.InventoryError)):
                provision.ensure(cloud)
            self.assertEqual(cloud.writes, [])

    def test_failure_to_confirm_policy_is_fatal(self):
        cloud = Fake(ignore_patch=True)
        with self.assertRaises(provision.ProvisionError):
            provision.ensure(cloud)
        self.assertEqual([w[0] for w in cloud.writes], ["POST", "PATCH"])

if __name__ == "__main__":
    unittest.main()
