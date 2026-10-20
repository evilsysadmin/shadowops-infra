"""Offline CD safety gates: staging only, immutable images and verified receipts."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
YML = ROOT / ".github/workflows/chronicles-api-staging.yml"


class StagingConvergenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(YML.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    def test_source_ci_and_manual_entrypoint_retained(self):
        events = self.workflow["on"]
        self.assertIn("workflow_dispatch", events)
        self.assertIn("push", events)
        self.assertIn("schedule", events)
        self.assertIn("17 * * * *", [row["cron"] for row in events["schedule"]])
        self.assertIn("provision", events["workflow_dispatch"]["inputs"]["action"]["options"])
        self.assertIn("deploy", events["workflow_dispatch"]["inputs"]["action"]["options"])

    def test_auto_deploy_is_limited_to_trusted_infra_main(self):
        admit = self.workflow["jobs"]["admit"]
        self.assertIn("refs/heads/main", admit["if"])
        self.assertIn("evilsysadmin/shadowops-infra", admit["if"])
        self.assertIn("inputs.action == 'deploy'", admit["if"])
        self.assertIn("schedule", admit["if"])
        self.assertIn("push", admit["if"])
        self.assertIn("actions", admit["permissions"])
        self.assertIn("needs.admit.outputs.deploy_needed", self.workflow["jobs"]["deploy"]["if"])

    def test_staging_source_remains_current_immediately_before_mutation(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        labels = [step.get("name", "") for step in steps]
        guard = "Reject a superseded staging source before touching OCI"
        self.assertLess(labels.index(guard), labels.index("Execute only the restricted Chronicles API deployer"))
        code = next(step["run"] for step in steps if step.get("name") == guard)
        self.assertIn("commits/main", code)
        self.assertIn("ADMITTED_SHA", code)
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_BLOCKED", code)
        self.assertIn("inputs.environment != 'production'",
                      next(step["if"] for step in steps if step.get("name") == guard))

    def test_receipt_is_created_only_after_three_live_smokes(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        names = [step.get("name", "") for step in steps]
        self.assertLess(names.index("Execute only the restricted Chronicles API deployer"),
                        names.index("Public smoke through the Chronicles tunnel"))
        self.assertLess(names.index("Public smoke through the Chronicles tunnel"),
                        names.index("Player-path smoke (register, run, save, reload; account always deleted)"))
        self.assertLess(names.index("Player-path smoke (register, run, save, reload; account always deleted)"),
                        names.index("Record successfully verified staging generation"))
        receipt = next(step for step in steps
                       if step.get("name") == "Publish verified generation receipt (idempotent future sync)")
        self.assertEqual(receipt["uses"], "actions/upload-artifact@v4")
        self.assertIn("inputs.environment != 'production'", receipt["if"])
        self.assertIn("source_sha", receipt["with"]["name"])

    def test_admission_is_attested_and_auto_sync_does_not_redeploy_same_sha(self):
        steps = self.workflow["jobs"]["admit"]["steps"]
        candidate = next(s for s in steps if s.get("id") == "candidate")
        admission = next(s for s in steps if s.get("id") == "admission")
        # The trusted receipt gate checks the successful run and main
        # provenance; the workflow must not maintain its own artifact counter.
        self.assertIn("chronicles_api_before_pages.py --receipt-only", candidate["run"])
        self.assertIn("CHRONICLES_API_RECEIPT_CHECK_INCONCLUSIVE", candidate["run"])
        self.assertNotIn("workflow_run.head_branch", candidate["run"])
        self.assertIn("deploy_needed=false", candidate["run"])
        self.assertIn("workflow_dispatch", candidate["run"])
        self.assertIn("gh attestation verify", admission["run"])
        self.assertIn("linux\",\"arm64", admission["run"])
        self.assertIn("--source-digest", admission["run"])


    def test_production_api_receipt_requires_real_public_smoke(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        names = [step.get("name", "") for step in steps]
        smoke = names.index("Public smoke through the Chronicles tunnel")
        record = names.index("Record successfully verified production API generation")
        upload = names.index("Save verified production API receipt for Pages promotion")
        self.assertLess(smoke, record)
        self.assertLess(record, upload)
        self.assertEqual(steps[record]["if"], "inputs.environment == 'production'")
        self.assertEqual(steps[upload]["if"], "inputs.environment == 'production'")
        self.assertIn("chronicles-api-production-", steps[upload]["with"]["name"])
        self.assertIn("source_sha", steps[upload]["with"]["name"])
        self.assertIn("api_image_digest", steps[record]["run"])
        # A production receipt is NEVER created by staging's automatic polls.
        self.assertEqual(steps[-2]["name"], "Record successfully verified production API generation")



if __name__ == "__main__":
    unittest.main()
