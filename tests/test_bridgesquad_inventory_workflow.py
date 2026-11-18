"""Prove that the one-time Bridge Squad inventory-on-merge is read-only and owner-scoped."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FLOW=ROOT / '.github/workflows/bridgesquad-pages-inventory.yml'
SCRIPT=ROOT / 'scripts/bridgesquad_pages_readiness.py'

class BridgeSquadInventoryWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flow=FLOW.read_text(encoding='utf-8')
        cls.script=SCRIPT.read_text(encoding='utf-8')

    def test_main_only_owner_only_and_no_pr_secrets(self):
        job=self.flow.split('\n  inventory:\n',1)[1]
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'",job)
        self.assertIn("github.ref == 'refs/heads/main'",job)
        self.assertIn("github.event_name == 'workflow_dispatch'",job)
        self.assertIn("github.event_name == 'push'",job)
        self.assertNotIn("github.event_name == 'pull_request'",job)
        self.assertIn('needs: contracts',job)
        self.assertIn('environment:\n      name: staging',job)

    def test_secrets_only_in_protected_inventory_job(self):
        contracts=self.flow.split('\n  inventory:\n',1)[0]
        inventory=self.flow.split('\n  inventory:\n',1)[1]
        self.assertNotIn('secrets.CLOUDFLARE',contracts)
        self.assertIn('secrets.CLOUDFLARE_API_TOKEN',inventory)
        self.assertIn('secrets.CLOUDFLARE_ACCOUNT_ID',inventory)
        self.assertIn('python3 scripts/bridgesquad_pages_readiness.py inspect',inventory)
        self.assertIn('permissions:\n      contents: read',inventory)
        for forbidden in ('wrangler','cloudflare/pages','actions/deploy-pages',
                          'github-script','gh api --method','oci', 'curl -X POST'):
            self.assertNotIn(forbidden.lower(),inventory.lower())

    def test_script_has_fixed_project_and_get_only(self):
        self.assertIn('PROJECT = "bridgesquad-production"',self.script)
        self.assertIn('HOST = "bridgesquad.shadowops.dpdns.org"',self.script)
        self.assertIn('method="GET"',self.script)
        for forbidden in ('method="POST"','method="PUT"','method="PATCH"',
                          'method="DELETE"','subprocess.run','os.system'):
            self.assertNotIn(forbidden,self.script)

    def test_inventory_results_cannot_claim_authenticated_delivery(self):
        self.assertIn('"identity_gate": "not-verified"',self.script)
        self.assertIn('"deployment": "not-verified"',self.script)
        self.assertIn('No Cloudflare mutations',self.script)

if __name__ == '__main__':
    unittest.main()
