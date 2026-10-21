"""One-shot staging guide diagnosis may not publish or certify a release."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/chronicles-guide-public-census.yml"


class GuideCensusWorkflow(unittest.TestCase):
    def test_runs_only_when_its_own_workflow_lands_on_main(self):
        workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        trigger = workflow["on"]
        self.assertNotIn("schedule", trigger)
        self.assertNotIn("workflow_dispatch", trigger)
        self.assertEqual(trigger["push"]["branches"], ["main"])
        self.assertEqual(trigger["push"]["paths"], [
            ".github/workflows/chronicles-guide-public-census.yml"
        ])
        self.assertEqual(workflow["permissions"], {"contents": "read"})

    def test_does_not_publish_or_issue_verified_release_receipt(self):
        workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        job = workflow["jobs"]["guide-census"]
        self.assertEqual(job["environment"]["name"], "staging")
        steps = job["steps"]
        run_script = "\n".join(step.get("run", "") for step in steps)
        self.assertNotIn("wrangler", run_script.lower())
        self.assertNotIn("chronicles_pages.py", run_script)
        self.assertNotIn("oci_chronicles_api_release", run_script)
        self.assertNotIn("chronicles-pages-staging-", WORKFLOW.read_text())
        self.assertNotIn("chronicles-api-staging-", WORKFLOW.read_text())
        self.assertNotIn("actions/upload-release-asset", WORKFLOW.read_text())
        self.assertIn("CHRONICLES_GUIDE_DIAGNOSTIC_ONLY_NO_RELEASE_RECEIPT", run_script)
        self.assertIn("node smoke/public-staging.mjs", run_script)
        self.assertIn("CHRONICLES_STAGING_INVITE_CODE", WORKFLOW.read_text())
        self.assertIn("CHRONICLES_DIAGNOSTIC_PUBLIC_SHA", run_script)
        self.assertIn("origin=\"https://staging.chronicles.shadowops.dpdns.org\"", run_script.replace("'", "\""))
        artifact = steps[-1]
        self.assertEqual(artifact["if"], "always()")
        self.assertEqual(artifact["with"]["retention-days"], "3")
        self.assertIn("first-steps-duplicate", artifact["with"]["path"])


if __name__ == "__main__":
    unittest.main()
