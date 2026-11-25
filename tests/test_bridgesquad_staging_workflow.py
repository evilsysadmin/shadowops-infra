"""The one-click staging workflow is manual, protected, ordered and staging-only."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / ".github/workflows/bridgesquad-staging.yml").read_text()
FLOW = yaml.safe_load(TEXT)


class StagingWorkflowTests(unittest.TestCase):
    def test_mutating_job_is_manual_main_only_in_staging_environment(self):
        job = FLOW["jobs"]["activate"]
        self.assertIn("github.event_name == 'workflow_dispatch'", job["if"])
        self.assertIn("inputs.action == 'activate'", job["if"])
        self.assertIn("github.ref == 'refs/heads/main'", job["if"])
        self.assertEqual(job["environment"], "staging")
        self.assertEqual(job["needs"], "contracts")
        self.assertNotIn("secrets.", str(FLOW["jobs"]["contracts"]["steps"]))
        self.assertNotIn("environment", FLOW["jobs"]["contracts"])

    def test_order_seal_deploy_verify_bind_then_dns_then_audit(self):
        runs = [s.get("run", "") for s in FLOW["jobs"]["activate"]["steps"]]
        idx = lambda needle: next(i for i, r in enumerate(runs) if needle in r)
        order = [idx("staging.py package"), idx("staging.py provision"), idx("wrangler@"),
                 idx("staging.py postdeploy"), idx("staging.py bind"), idx("staging.py attach"),
                 idx("staging.py audit")]
        self.assertEqual(order, sorted(order))
        deploy = runs[idx("wrangler@")]
        self.assertIn("--project-name bridgesquad-staging", deploy)
        self.assertNotIn("bridgesquad-production", TEXT)

    def test_no_untrusted_input_is_interpolated_into_shell(self):
        for job in FLOW["jobs"].values():
            for step in job.get("steps", []):
                self.assertNotIn("${{ inputs.", step.get("run", ""))


if __name__ == "__main__":
    unittest.main()
