"""Offline release-train gates, based on actual Pages/Identity security code."""
import copy
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_dns_quarantine as q
import bridgesquad_production_release as release
import bridgesquad_production_proof_bind as proof
import bridgesquad_pages_readiness as readiness
import test_bridgesquad_dns_quarantine as fixture

OLD = "a" * 40
NEW = "b" * 40
ID_OLD = "55555555-5555-4555-8555-555555555555"
ID_NEW = "66666666-6666-4666-8666-666666666666"


def public():
    return {"public_surface": "present", "service": "present",
            "jwks": "present", "login": "present"}


def audit(client, *, allow_bound=False):
    with mock.patch.object(q.socket, "getaddrinfo", return_value=[("ip",)]):
        return q.audit(client, guest=fixture.guest,
                       web=fixture.web, allow_bound=allow_bound)


def ready():
    client = fixture.FakeClient()
    # Attach DNS only before the production secret is introduced.
    q.attach(client, guest=fixture.guest)
    client.project["canonical_deployment"]["id"] = ID_OLD
    client.project["latest_deployment"]["id"] = ID_OLD
    client.project["deployment_configs"]["production"]["env_vars"] = {
        proof.KEY: {"type": "secret_text"},
    }
    return client


class ReleaseAdmissionTests(unittest.TestCase):
    def test_green_preflight_with_existing_protected_game_sha(self):
        client = ready()
        r = release.preflight(client, OLD, NEW, audit=audit, public=public)
        self.assertEqual(r["prior_source_sha"], OLD)
        self.assertEqual(r["target_source_sha"], NEW)
        self.assertEqual(r["prior_deployment_id"], ID_OLD)
        self.assertEqual(r["guest"], "denied")
        self.assertEqual(r["identity"], "proof-bound-unverified")

    def test_postflight_requires_new_canonical_id_source_and_guest_denial(self):
        client = ready()
        with self.assertRaises(release.Refused):
            release.postflight(client, NEW, ID_OLD, audit=audit, public=public)
        client.project["canonical_deployment"]["deployment_trigger"]["metadata"]["commit_hash"] = NEW
        client.project["latest_deployment"]["deployment_trigger"]["metadata"]["commit_hash"] = NEW
        with self.assertRaises(release.Refused):
            release.postflight(client, NEW, ID_OLD, audit=audit, public=public)
        client.project["canonical_deployment"]["id"] = ID_NEW
        client.project["latest_deployment"]["id"] = ID_NEW
        r = release.postflight(client, NEW, ID_OLD, audit=audit, public=public)
        self.assertEqual(r["source_sha"], NEW)
        self.assertEqual(r["deployment_id"], ID_NEW)
        self.assertEqual(r["aliases"], "2")
        self.assertEqual(r["authenticated_browser"], "NOT_VERIFIED")

    def test_refuse_stale_live_sha_redelivery_and_unpinned_target(self):
        c = ready()
        for old, new in ((NEW, OLD), (OLD, OLD), ("z"*40, NEW),
                         ("a"*39, NEW), (OLD, "B"*40), (OLD, "")):
            with self.subTest(old=old, new=new), self.assertRaises(release.Refused):
                release.preflight(c, old, new, audit=audit, public=public)

    def test_no_release_without_single_encrypted_production_proof(self):
        c = ready()
        cases = [
            {},
            {proof.KEY: {"type": "plain_text"}},
            {"extra": {"type": "secret_text"}},
            {proof.KEY: {"type": "secret_text"}, "extra": {"type": "secret_text"}},
        ]
        for change in cases:
            c.project["deployment_configs"]["production"]["env_vars"] = copy.deepcopy(change)
            with self.subTest(change=change), self.assertRaises((release.Refused, q.QuarantineError)):
                release.preflight(c, OLD, NEW, audit=audit, public=public)
        c = ready()
        c.project["deployment_configs"]["preview"]["env_vars"] = {proof.KEY: {"type": "secret_text"}}
        with self.assertRaises(q.QuarantineError):
            release.preflight(c, OLD, NEW, audit=audit, public=public)

    def test_fail_closed_if_idp_unavailable_or_guest_gate_returns_game(self):
        c = ready()
        with self.assertRaises(release.Refused):
            release.preflight(c, OLD, NEW, audit=audit,
                              public=lambda: {"public_surface": "not-ready"})
        def game_leak(client, **kwargs):
            return {"source_sha": OLD, "production_identity": "proof-bound-unverified",
                    "https": "200-game", "assets": "leaked"}
        with self.assertRaises(release.Refused):
            release.preflight(c, OLD, NEW, audit=game_leak, public=public)

    def test_unknown_deployment_id_and_foreign_domain_are_denied(self):
        c = ready()
        c.project["canonical_deployment"].pop("id")
        with self.assertRaises(release.Refused):
            release.preflight(c, OLD, NEW, audit=audit, public=public)
        c = ready()
        c.project["domains"].append("other.example.org")
        with self.assertRaises((q.QuarantineError, readiness.InventoryError)):
            release.preflight(c, OLD, NEW, audit=audit, public=public)

    def test_cli_has_read_only_contract_and_refuses_missing_cloudflare(self):
        self.assertEqual(release.main(["plan"]), 0)
        self.assertEqual(release.main(["preflight", OLD]), 2)
        with mock.patch.dict(release.os.environ, {}, clear=True):
            self.assertEqual(release.main(["preflight", OLD, NEW]), 1)


if __name__ == "__main__":
    unittest.main()
