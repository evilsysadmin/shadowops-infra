"""Offline contracts for Bridge Squad's single-audience Atlas extension,
and order independence with the Star Adventures extension."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from identity_staging_atlas_bridgesquad_config import candidate_config, BridgeSquadConfigBlocked
from identity_staging_atlas_staradvs_config import (
    candidate_config as staradvs_config, StarAdvsConfigBlocked)
from test_identity_staging_atlas_staradvs_config import fixture, proof


def both_pending():
    active, vault = fixture()  # Vault already carries a pending staradvs proof
    vault["consumers"]["bridgesquad"] = proof("q")
    return active, vault


class BridgeSquadCandidateTests(unittest.TestCase):
    def test_only_bridgesquad_added_and_pending_staradvs_ignored(self):
        active, vault = both_pending()
        before = deepcopy((active, vault))
        result = candidate_config(active, vault)
        expected = deepcopy(active)
        expected["consumers"]["bridgesquad"] = proof("q")
        self.assertEqual(result, expected)
        self.assertNotIn("staradvs", result["consumers"])
        self.assertEqual((active, vault), before)

    def test_staradvs_release_not_blocked_by_pending_bridgesquad(self):
        active, vault = both_pending()
        result = staradvs_config(active, vault)
        self.assertEqual(result["consumers"]["staradvs"], proof("s"))
        self.assertNotIn("bridgesquad", result["consumers"])

    def test_either_order_reaches_same_final_consumers(self):
        active, vault = both_pending()
        a = staradvs_config(candidate_config(active, vault), vault)
        b = candidate_config(staradvs_config(active, vault), vault)
        self.assertEqual(a, b)
        self.assertEqual(set(a["consumers"]) - set(active["consumers"]), {"staradvs", "bridgesquad"})

    def test_unexpected_consumer_changes_block(self):
        for mutation in (
            lambda a, v: v["consumers"].pop("bridgesquad"),
            lambda a, v: v["consumers"].pop("football"),
            lambda a, v: v["consumers"].update(football=proof("x")),
            lambda a, v: v["consumers"].update(extra=proof("x")),
            lambda a, v: v["consumers"].update(bridgesquad=proof("d")),
            lambda a, v: v["consumers"].update(bridgesquad="bad"),
            lambda a, v: a["consumers"].update(bridgesquad=proof("q")),
            lambda a, v: (a["consumers"].pop("snooker"), v["consumers"].pop("snooker")),
        ):
            active, vault = both_pending()
            mutation(active, vault)
            before = deepcopy((active, vault))
            with self.assertRaises(BridgeSquadConfigBlocked):
                candidate_config(active, vault)
            self.assertEqual((active, vault), before)

    def test_staradvs_still_rejects_unknown_pending_consumers(self):
        active, vault = fixture()
        vault["consumers"]["extra"] = proof("x")
        with self.assertRaises(StarAdvsConfigBlocked):
            staradvs_config(active, vault)

    def test_non_database_custody_change_blocks(self):
        for field in ("signing_seed", "tls_private_key_pem", "tls_certificate_pem",
                      "admin_inventory_access_history", "environment"):
            active, vault = both_pending()
            vault[field] = "unexpected"
            with self.assertRaises(BridgeSquadConfigBlocked):
                candidate_config(active, vault)


if __name__ == "__main__":
    unittest.main()
