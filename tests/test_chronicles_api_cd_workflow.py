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

    def test_receipt_is_created_only_after_three_live_smokes(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        names = [step.get("name", "") for step in steps]
        self.assertLess(names.index("Execute only the restricted Chronicles API deployer"),
                        names.index("Public smoke through the Chronicles tunnel"))
        self.assertLess(names.index("Public smoke through the Chronicles tunnel"),
                        names.index("Player-path smoke (register, run, save, reload; account always deleted)"))
        self.assertLess(names.index("Player-path smoke (register, run, save, reload; account always deleted)"),
                        names.index("Record successfully verified staging generation"))
        receipt = steps[-1]
        self.assertEqual(receipt["uses"], "actions/upload-artifact@v4")
        self.assertIn("inputs.environment != 'production'", receipt["if"])
        self.assertIn("source_sha", receipt["with"]["name"])

    def test_admission_is_attested_and_auto_sync_does_not_redeploy_same_sha(self):
        steps = self.workflow["jobs"]["admit"]["steps"]
        candidate = next(s for s in steps if s.get("id") == "candidate")
        admission = next(s for s in steps if s.get("id") == "admission")
        self.assertIn("actions/artifacts", candidate["run"])
        self.assertIn("workflow_run.head_branch", candidate["run"])
        self.assertIn("deploy_needed=false", candidate["run"])
        self.assertIn("workflow_dispatch", candidate["run"])
        self.assertIn("gh attestation verify", admission["run"])
        self.assertIn("linux\",\"arm64", admission["run"])
        self.assertIn("--source-digest", admission["run"])


if __name__ == "__main__":
    unittest.main()
