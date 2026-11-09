import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_staging_publish as pub
import snooker_pages_readiness as readiness
from snooker_pages_provision import ProvisionError

ACCOUNT = "a"*32
P = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
ZONE = "/zones?" + urlencode({"name": readiness.ZONE, "account.id": ACCOUNT})
DNS = "/zones/z-one/dns_records?" + urlencode({"name": readiness.HOST, "per_page": 100})
DOM = P + "/domains/" + readiness.HOST
PROOF = "soc1_" + "Q"*43

class Fake:
    account = ACCOUNT
    def __init__(self, *, private=True, unknown_binding=False):
        flags = ["global_fetch_strictly_public"]
        self.project = {
            "name": readiness.PROJECT, "production_branch": "main",
            "subdomain": "snooker-staging.pages.dev", "source": None, "domains": [],
            "deployment_configs": {
                "production": {"fail_open": not private, "compatibility_flags": flags,
                               "env_vars": {"UNKNOWN": {"type": "plain_text"}} if unknown_binding else {}},
                "preview": {"fail_open": False, "compatibility_flags": flags,
                            "env_vars": {}},
            },
        }
        self.domain = None
        self.dns = []
        self.writes = []

    def get(self, path):
        if path == ZONE: return [{"name": readiness.ZONE, "id": "z-one"}]
        if path == P: return self.project
        if path == DOM: return self.domain
        if path == DNS: return list(self.dns)
        raise AssertionError(path)

    def write(self, method, path, value):
        self.writes.append((method, path))
        if method == "PATCH":
            production = value["deployment_configs"]["production"]
            if production.get("fail_open") is not False or "global_fetch_strictly_public" not in production.get("compatibility_flags", []):
                raise AssertionError("Secret binding must retain explicit fail-closed Pages policy")
            self.project["deployment_configs"]["production"]["env_vars"] = production["env_vars"]
            return self.project
        if path == P + "/domains":
            self.domain = {"name": readiness.HOST, "status": "active"}
            self.project["domains"] = [readiness.HOST, "snooker-staging.pages.dev"]
            return self.domain
        if path == "/zones/z-one/dns_records":
            self.dns.append({"name": readiness.HOST, "type": "CNAME", "proxied": True,
                             "content": "snooker-staging.pages.dev"})
            return self.dns[0]
        raise AssertionError(path)

class PublishTests(unittest.TestCase):
    def test_isolated_proof_only_binds_to_private_production(self):
        cloud = Fake()
        pub.bind(cloud, PROOF)
        self.assertEqual(cloud.writes, [("PATCH", P)])
        cfg = cloud.project["deployment_configs"]
        self.assertEqual(set(cfg["production"]["env_vars"]), {pub.KEY})
        self.assertEqual(cfg["preview"]["env_vars"], {})
        self.assertIs(cfg["production"]["fail_open"], False)

    def test_unknown_binding_or_fail_open_denies_without_writes(self):
        for cloud in (Fake(private=False), Fake(unknown_binding=True)):
            with self.subTest(cloud=cloud.__dict__), self.assertRaises(ProvisionError):
                pub.bind(cloud, PROOF)
            self.assertEqual(cloud.writes, [])
        with self.assertRaises(ProvisionError):
            pub.bind(Fake(), "soc1_not-a-real-proof")

    def test_domain_creation_denies_public_alias_and_requires_bound_proof(self):
        cloud = Fake()
        with self.assertRaises(ProvisionError):
            pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])
        pub.bind(cloud, PROOF)
        cloud.writes.clear()
        with self.assertRaises(ProvisionError):
            pub.attach_domain(cloud, lambda _:200)
        self.assertEqual(cloud.writes, [])
        pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [("POST", P+"/domains"), ("POST", "/zones/z-one/dns_records")])
        cloud.writes.clear()
        pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])

    def test_foreign_dns_can_never_be_overwritten(self):
        cloud = Fake()
        pub.bind(cloud, PROOF)
        cloud.writes.clear()
        cloud.dns = [{"name": readiness.HOST, "type": "CNAME", "proxied": True,
                      "content": "foreign.pages.dev"}]
        with self.assertRaises((readiness.InventoryError, ProvisionError)):
            pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])

    def test_issuer_login_must_advertise_exact_snooker_origin(self):
        pub.issuer_ready(lambda _: b"ready https://staging.snooker.shadowops.dpdns.org/?shadowops=central")
        for body in (b"login football", b"redirect https://staging.snooker.shadowops.dpdns.org.evil/"):
            with self.assertRaises(ProvisionError):
                pub.issuer_ready(lambda _:body)

    def test_guest_smoke_requires_both_alias_and_custom_host_denial(self):
        pub.smoke_guest(lambda u:404 if "pages.dev" in u else 401)
        with self.assertRaises(ProvisionError):
            pub.smoke_guest(lambda u:200)
