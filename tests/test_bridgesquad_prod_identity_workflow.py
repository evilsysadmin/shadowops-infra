"""Public production IdP readiness must never borrow staging cookies or secrets."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FLOW=ROOT/".github/workflows/bridgesquad-prod-identity-readiness.yml"
CONTRACT=ROOT/"config/identity/platform-contract.json"


class ProductionReadinessWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow=FLOW.read_text(encoding="utf-8")
        cls.cfg=json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.contracts,cls.job=cls.workflow.split("\n  public-readiness:\n",1)

    def test_no_production_network_from_pr_and_only_main_or_schedule(self):
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'",self.job)
        self.assertIn("github.ref == 'refs/heads/main'",self.job)
        for name in ("push","schedule","workflow_dispatch"):
            self.assertIn("github.event_name == '"+name+"'",self.job)
        self.assertNotIn("github.event_name == 'pull_request'",self.job)
        self.assertIn("needs: contracts",self.job)
        self.assertIn("python3 scripts/bridgesquad_prod_identity_probe.py inspect",self.job)
        self.assertIn("permissions:\n      contents: read",self.job)
        self.assertIn("schedule:\n    - cron: '41 8 * * *'",self.workflow)

    def test_no_credentials_or_cloud_resources_in_public_probe(self):
        for blocked in ("secrets.", "CLOUDFLARE_", "OCI_", "GH_TOKEN",
                        "wrangler", "pages deploy", "actions/deploy-pages",
                        "login-password", "api/identity/token", "staging-operations"):
            with self.subTest(blocked=blocked):
                self.assertNotIn(blocked.lower(), self.job.lower())
        self.assertIn("No Cloudflare/DNS/Identity mutation",self.job)

    def test_contract_keeps_bridge_squad_only_in_isolated_production(self):
        prod=self.cfg["environments"]["production"]
        staging=self.cfg["environments"]["staging"]
        self.assertEqual(prod["issuer"],"https://id.shadowops.dpdns.org")
        self.assertEqual(staging["issuer"],"https://id-staging.shadowops.dpdns.org")
        consumers=[c for c in prod["consumers"] if c["audience"]=="bridgesquad"]
        self.assertEqual(len(consumers),1)
        self.assertEqual(consumers[0],{
            "audience":"bridgesquad",
            "origin":"https://bridgesquad.shadowops.dpdns.org",
            "status":"not-provisioned",
        })
        # Staging may host its own isolated Bridge Squad consumer, but never the production origin.
        staged=[c for c in staging["consumers"] if c["audience"]=="bridgesquad"]
        self.assertLessEqual(len(staged),1)
        for c in staged:
            self.assertEqual(c["origin"],"https://staging.bridgesquad.shadowops.dpdns.org")
        self.assertFalse(any(c["origin"]=="https://bridgesquad.shadowops.dpdns.org" for c in staging["consumers"]))
        for key in ("shared_user_database","shared_signing_keys","shared_cookie_scope",
                    "shared_authorization","cross_environment_trust"):
            self.assertIs(self.cfg[key],False)


if __name__ == "__main__":
    unittest.main()
