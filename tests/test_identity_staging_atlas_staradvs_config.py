"""Offline contracts for Star Adventures' single-audience Atlas extension."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from identity_staging_atlas_staradvs_config import candidate_config, StarAdvsConfigBlocked


def proof(c):
    return "soc1_" + c * 43


def fixture():
    active = {
        "environment": "staging",
        "mongo_uri": "mongodb+srv://app:dummy@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin",
        "admin_inventory_mongo_uri": "mongodb+srv://inventory:dummy@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin",
        "mongo_ca_pem": "", "mongo_privilege_mode": "database-scoped",
        "admin_inventory_access_history": True,
        "signing_seed": "synthetic-seed", "tls_private_key_pem": "synthetic-key",
        "tls_certificate_pem": "synthetic-cert",
        "consumers": {k: proof(c) for k, c in [
            ("chess-studio", "a"), ("chronicles", "b"), ("football", "c"),
            ("snooker", "d"), ("pawn-action", "e"), ("cka-simulator", "f")]},
    }
    vault = deepcopy(active)
    vault.pop("mongo_privilege_mode")
    vault.update(mongo_uri="local-app", admin_inventory_mongo_uri="local-inventory",
                 mongo_ca_pem="local-ca")
    vault["consumers"]["staradvs"] = proof("s")
    return active, vault


class StarAdvsCandidateTests(unittest.TestCase):
    def test_only_new_audience_added(self):
        active, vault = fixture()
        before = deepcopy((active, vault))
        result = candidate_config(active, vault)
        expected = deepcopy(active)
        expected["consumers"]["staradvs"] = proof("s")
        self.assertEqual(result, expected)
        self.assertEqual((active, vault), before)
        result["consumers"]["snooker"] = proof("x")
        self.assertEqual((active, vault), before)

    def test_unexpected_consumer_changes_block(self):
        for mutation in (
            lambda a, v: v["consumers"].pop("staradvs"),
            lambda a, v: v["consumers"].pop("football"),
            lambda a, v: v["consumers"].update(football=proof("x")),
            lambda a, v: v["consumers"].update(extra=proof("x")),
            lambda a, v: v["consumers"].update(staradvs=proof("d")),
            lambda a, v: v["consumers"].update(staradvs="bad"),
            lambda a, v: a["consumers"].update(staradvs=proof("s")),
            lambda a, v: (a["consumers"].pop("snooker"), v["consumers"].pop("snooker")),
        ):
            active, vault = fixture()
            mutation(active, vault)
            before = deepcopy((active, vault))
            with self.assertRaises(StarAdvsConfigBlocked):
                candidate_config(active, vault)
            self.assertEqual((active, vault), before)

    def test_non_database_custody_change_blocks(self):
        for field in ("signing_seed", "tls_private_key_pem", "tls_certificate_pem",
                      "admin_inventory_access_history", "environment"):
            active, vault = fixture()
            vault[field] = "unexpected"
            with self.assertRaises(StarAdvsConfigBlocked):
                candidate_config(active, vault)

    def test_wrong_atlas_scope_and_connections_block(self):
        for mutation in (
            lambda a: a.update(mongo_privilege_mode="admin"),
            lambda a: a.update(mongo_ca_pem="unexpected"),
            lambda a: a.update(mongo_uri="mongodb://local"),
            lambda a: a.update(admin_inventory_mongo_uri=a["mongo_uri"]),
            lambda a: a.update(admin_inventory_mongo_uri=a["admin_inventory_mongo_uri"].replace("cluster.mongodb.net", "other.mongodb.net")),
        ):
            active, vault = fixture()
            mutation(active)
            with self.assertRaises(StarAdvsConfigBlocked):
                candidate_config(active, vault)


if __name__ == "__main__":
    unittest.main()
