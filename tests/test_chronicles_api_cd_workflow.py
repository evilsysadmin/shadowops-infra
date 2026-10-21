"""Offline CD safety gates: staging only, immutable images and verified receipts."""
from pathlib import Path
import os
import subprocess
import tempfile
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
        guard = "Skip a superseded staging source before touching OCI"
        self.assertLess(labels.index(guard), labels.index("Cache OCI SDK wheel downloads"))
        self.assertLess(labels.index(guard), labels.index("Execute only the restricted Chronicles API deployer"))
        step = next(step for step in steps if step.get("name") == guard)
        self.assertEqual(step["id"], "freshness")
        code = step["run"]
        self.assertIn("commits/main", code)
        self.assertIn("ADMITTED_SHA", code)
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_SKIPPED", code)
        self.assertIn("deploy=false", code)
        self.assertIn("deploy=true", code)
        self.assertIn("GITHUB_STEP_SUMMARY", code)
        self.assertEqual(step["if"], "inputs.environment != 'production'")

    def test_superseded_staging_never_mutates_oci_or_creates_receipts(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        by_name = {s.get("name"): s for s in steps if s.get("name")}
        any_live = "inputs.environment == 'production' || steps.freshness.outputs.deploy == 'true'"
        staging_only = "inputs.environment != 'production' && steps.freshness.outputs.deploy == 'true'"
        for name in [
            "Execute only the restricted Chronicles API deployer",
            "Public smoke through the Chronicles tunnel",
        ]:
            self.assertEqual(by_name[name]["if"], any_live, name)
        for name in [
            "Prove public staging API serves the admitted source SHA",
            "Player-path smoke (register, run, save, reload; account always deleted)",
            "Record successfully verified staging generation",
            "Publish verified generation receipt (idempotent future sync)",
        ]:
            self.assertEqual(by_name[name]["if"], staging_only, name)
        # Production still requires its own admission and receipt path.
        self.assertEqual(
            by_name["Require verified staging API and Pages before production mutation"]["if"],
            "inputs.environment == 'production'")
        self.assertEqual(
            by_name["Save verified production API receipt for Pages promotion"]["if"],
            "inputs.environment == 'production'")

    def test_freshness_probe_current_obsolete_or_unverifiable(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        script = next(s["run"] for s in steps if s.get("id") == "freshness")
        for current, admitted, gh_failed, expected_rc, expected_flag in [
            ("a" * 40, "a" * 40, False, 0, "deploy=true"),
            ("b" * 40, "a" * 40, False, 0, "deploy=false"),
            ("not-a-sha", "a" * 40, False, 64, ""),
            ("a" * 40, "bad-sha", False, 64, ""),
            ("a" * 40, "a" * 40, True, 4, ""),
        ]:
            with self.subTest(current=current, admitted=admitted, gh_failed=gh_failed):
                with tempfile.TemporaryDirectory(prefix="chronicles-stale-") as tmp:
                    fake_gh = Path(tmp) / "gh"
                    fake_gh.write_text(
                        '#!/bin/sh\n'
                        'if [ "$FAKE_GH_FAILURE" = "true" ]; then exit 4; fi\n'
                        'printf "%s\\n" "$FAKE_MAIN_SHA"\n',
                        encoding="utf-8")
                    fake_gh.chmod(0o755)
                    output = Path(tmp) / "output"
                    summary = Path(tmp) / "summary"
                    output.touch()
                    summary.touch()
                    env = {
                        **os.environ,
                        "PATH": tmp + os.pathsep + os.environ["PATH"],
                        "FAKE_MAIN_SHA": current,
                        "FAKE_GH_FAILURE": str(gh_failed).lower(),
                        "ADMITTED_SHA": admitted,
                        "GITHUB_OUTPUT": str(output),
                        "GITHUB_STEP_SUMMARY": str(summary),
                    }
                    run = subprocess.run(["bash", "-c", script], env=env,
                                         capture_output=True, text=True, timeout=6)
                    self.assertEqual(run.returncode, expected_rc, run.stderr)
                    self.assertEqual(output.read_text().strip(), expected_flag)
                    if expected_flag == "deploy=false":
                        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_SKIPPED", run.stdout)
                        self.assertIn("No OCI changes", summary.read_text())
                    if expected_rc != 0:
                        self.assertNotIn("deploy=true", output.read_text())

    def test_receipt_is_created_only_after_three_live_smokes(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        names = [step.get("name", "") for step in steps]
        self.assertLess(names.index("Execute only the restricted Chronicles API deployer"),
                        names.index("Public smoke through the Chronicles tunnel"))
        self.assertLess(names.index("Public smoke through the Chronicles tunnel"),
                        names.index("Prove public staging API serves the admitted source SHA"))
        self.assertLess(names.index("Prove public staging API serves the admitted source SHA"),
                        names.index("Player-path smoke (register, run, save, reload; account always deleted)"))
        revision = next(step for step in steps if
                        step.get("name") == "Prove public staging API serves the admitted source SHA")
        self.assertEqual(revision["if"], "inputs.environment != 'production'")
        self.assertIn("--public-sha-only", revision["run"])
        self.assertEqual(revision["env"]["EXPECTED_SHA"], "${{ needs.admit.outputs.source_sha }}")
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


    def test_oci_sdk_cache_only_stores_downloads_not_installed_runtime(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        cache = next(s for s in steps if s.get("name") == "Cache OCI SDK wheel downloads")
        install = next(s for s in steps if
                       "oci==2.185.2" in str(s.get("run", "")))
        self.assertLess(steps.index(cache), steps.index(install))
        self.assertEqual(cache["uses"], "actions/cache@v4")
        self.assertEqual(cache["with"]["path"], "~/.cache/pip")
        self.assertIn("runner.os", cache["with"]["key"])
        self.assertIn("py313-sdk-2.185.2", cache["with"]["key"])
        self.assertIn("oci==2.185.2", install["run"])
        gate = "inputs.environment == 'production' || steps.freshness.outputs.deploy == 'true'"
        self.assertEqual(install["if"], gate)
        self.assertEqual(cache["if"], gate)
        # Avoid cross-contaminating the separately provisioned OCI runtime.
        self.assertFalse(any(s.get("name") == "Cache OCI SDK wheel downloads"
                             for s in self.workflow["jobs"]["provision"]["steps"]))

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
