"""P0 platform identity topology tests: design-only, no network and no secrets."""
import json
from pathlib import Path
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "identity" / "platform-contract.json"


class IdentityPlatformContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.stage = cls.data["environments"]["staging"]
        cls.prod = cls.data["environments"]["production"]

    def test_explicitly_target_not_current_operational_state(self):
        self.assertEqual(self.data["status"], "design-only-not-deployed")
        self.assertEqual(set(self.data["environments"]), {"staging", "production"})
        self.assertIn("/issues/287", self.data["issue"])

    def test_identical_product_audiences_but_distinct_environment_origins(self):
        stage = {a["audience"]: a["origin"] for a in self.stage["consumers"]}
        prod = {a["audience"]: a["origin"] for a in self.prod["consumers"]}
        self.assertEqual(set(stage), {"chess-studio", "chronicles", "cka-simulator"})
        self.assertEqual(set(stage), set(prod))
        self.assertFalse(set(stage.values()) & set(prod.values()))
        for origin in stage.values():
            self.assertEqual(urlsplit(origin).scheme, "https")
            self.assertIn("staging.", origin)
        for origin in prod.values():
            self.assertEqual(urlsplit(origin).scheme, "https")
            self.assertNotIn("staging.", origin)

    def test_separate_trust_and_state_per_environment(self):
        fields = ["issuer", "dns_host", "database", "database_role", "signing_key_scope"]
        for field in fields:
            self.assertTrue(self.stage[field])
            self.assertTrue(self.prod[field])
            self.assertNotEqual(self.stage[field], self.prod[field], field)
        self.assertEqual(urlsplit(self.stage["issuer"]).hostname, self.stage["dns_host"])
        self.assertEqual(urlsplit(self.prod["issuer"]).hostname, self.prod["dns_host"])
        for flag in ("cross_environment_trust", "global_admin_impersonation", "shared_user_database",
                     "shared_signing_keys", "shared_cookie_scope", "shared_authorization"):
            self.assertIs(self.data[flag], False, flag)

    def test_cookies_are_host_only_and_independent(self):
        self.assertNotEqual(self.stage["cookie"]["name"], self.prod["cookie"]["name"])
        for env in (self.stage, self.prod):
            cookie = env["cookie"]
            self.assertIsNone(cookie["domain"], "No cookie Domain attr: host-only scope")
            self.assertTrue(cookie["http_only"] and cookie["secure"])
            self.assertEqual(cookie["same_site"], "Lax")
        # The new staging host uses the browser-enforced __Host- protection
        # against sibling-subdomain cookie planting. That prefix requires /.
        self.assertTrue(self.stage["cookie"]["name"].startswith("__Host-"))
        self.assertEqual(self.stage["cookie"]["path"], "/")
        self.assertEqual(self.prod["cookie"]["path"], "/api/identity")

    def test_issuer_urls_properly_scoped_and_https(self):
        for env in (self.stage, self.prod):
            url = urlsplit(env["issuer"])
            self.assertEqual(url.scheme, "https")
            self.assertEqual(url.username, None)
            self.assertEqual(url.password, None)
            self.assertNotIn(url.hostname, ("localhost", "127.0.0.1"))
            self.assertEqual(url.path, "")
            self.assertEqual(url.query, "")
        self.assertEqual(self.stage["issuer"], "https://id-staging.shadowops.dpdns.org")
        self.assertEqual(self.prod["issuer"], "https://id.shadowops.dpdns.org")

    def test_token_requires_explicit_issuer_audience_and_stable_subject(self):
        token = self.data["token_target"]
        self.assertEqual(token["algorithm"], "EdDSA")
        self.assertGreater(token["ttl_seconds"], 0)
        self.assertLessEqual(token["ttl_seconds"], 3600)
        self.assertGreaterEqual({"iss", "aud", "sub", "exp", "iat", "nbf"},
                                set(token["required_claims"]))
        self.assertEqual(token["public_keys_path"], "/api/identity/jwks")
        self.assertIn("opaque", token["subject_contract"])

    def test_cka_is_only_static_public_preview_before_idp(self):
        candidate = next(p for p in self.prod["consumers"] if p["audience"] == "cka-simulator")
        self.assertEqual(candidate["status"], "static-preview-only")
        self.assertTrue(self.data["production_policy"]["no_public_lab_auth_without_sso"])


if __name__ == "__main__":
    unittest.main()
