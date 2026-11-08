import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_pages_readiness as readiness


ACCOUNT = "a" * 32
ZONE_ID = "zone-id"
QUERY = urlencode({"name": readiness.ZONE, "account.id": ACCOUNT})
ZONES = "/zones?" + QUERY
PROJECT = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
DOMAIN = PROJECT + "/domains/" + readiness.HOST
DNS = "/zones/" + ZONE_ID + "/dns_records?" + urlencode(
    {"name": readiness.HOST, "per_page": 100}
)
ALIAS = "snooker-staging.pages.dev"


class FakeCloudflare:
    account = ACCOUNT

    def __init__(self, data):
        self.data = data
        self.read_paths = []

    def get(self, path):
        self.read_paths.append(path)
        if path not in self.data:
            raise AssertionError("Unexpected read path: " + path)
        return self.data[path]


def inventory(project=None, domain=None, records=None, zones=None):
    data = {
        ZONES: [{"name": readiness.ZONE, "id": ZONE_ID}] if zones is None else zones,
        PROJECT: project,
        DNS: [] if records is None else records,
    }
    if project is not None:
        data[DOMAIN] = domain
    return FakeCloudflare(data)


def own_project():
    return {"name": readiness.PROJECT, "production_branch": "main",
            "subdomain": ALIAS, "source": None, "domains": []}


def own_record():
    return {"name": readiness.HOST, "type": "CNAME",
            "content": ALIAS, "proxied": True}


class SnookerReadinessTests(unittest.TestCase):
    def test_absent_resources_are_safe_and_not_claimed_as_deployed(self):
        cf = inventory()
        self.assertEqual(readiness.inspect(cf), {
            "project": "absent", "domain": "absent", "dns": "absent",
            "identity_gate": "not-verified", "deployment": "not-verified"})
        self.assertEqual(cf.read_paths, [ZONES, PROJECT, DNS])

    def test_existing_owned_project_domain_dns_still_does_not_prove_identity(self):
        project = own_project()
        project["domains"] = [readiness.HOST, ALIAS]
        cf = inventory(project, {"name": readiness.HOST, "status": "active"},
                       [own_record()])
        self.assertEqual(readiness.inspect(cf)["dns"], "present")
        self.assertEqual(readiness.inspect(cf)["identity_gate"], "not-verified")

    def test_project_with_foreign_branch_or_source_is_rejected(self):
        for changed in ({"production_branch": "production"},
                        {"source": {"type": "github"}}):
            project = own_project()
            project.update(changed)
            with self.subTest(changed=changed), self.assertRaises(readiness.InventoryError):
                readiness.inspect(inventory(project))

    def test_unknown_alias_or_foreign_domain_is_rejected(self):
        for changed in ({"subdomain": "another-game.pages.dev"},
                        {"domains": ["staging.other.shadowops.dpdns.org"]}):
            project = own_project()
            project.update(changed)
            with self.subTest(changed=changed), self.assertRaises(readiness.InventoryError):
                readiness.inspect(inventory(project))

    def test_existing_dns_without_project_fails_closed(self):
        with self.assertRaises(readiness.InventoryError):
            readiness.inspect(inventory(records=[own_record()]))

    def test_wrong_dns_target_or_unproxied_record_fails_closed(self):
        for changed in ({"content": "foreign.pages.dev"}, {"proxied": False},
                        {"type": "A"}):
            record = own_record()
            record.update(changed)
            with self.subTest(changed=changed), self.assertRaises(readiness.InventoryError):
                readiness.inspect(inventory(own_project(), records=[record]))

    def test_duplicate_dns_or_ambiguous_zone_fails_closed(self):
        with self.assertRaises(readiness.InventoryError):
            readiness.inspect(inventory(own_project(), records=[own_record(), own_record()]))
        with self.assertRaises(readiness.InventoryError):
            readiness.inspect(inventory(zones=[{"name": readiness.ZONE, "id": "one"},
                                               {"name": readiness.ZONE, "id": "two"}]))

    def test_unhealthy_or_inconsistent_pages_domain_fails_closed(self):
        project = own_project()
        project["domains"] = [readiness.HOST]
        with self.assertRaises(readiness.InventoryError):
            readiness.inspect(inventory(project, domain=None))
        with self.assertRaises(readiness.InventoryError):
            readiness.inspect(inventory(project, {"name": readiness.HOST, "status": "error"}))

    def test_credentials_are_required_and_no_default_account_is_assumed(self):
        with self.assertRaises(readiness.InventoryError):
            readiness.CloudflareClient({})
        with self.assertRaises(readiness.InventoryError):
            readiness.CloudflareClient({"CLOUDFLARE_ACCOUNT_ID": ACCOUNT})


if __name__ == "__main__":
    unittest.main()
