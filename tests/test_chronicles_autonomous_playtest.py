"""Guardrails for the scheduled real Chronicles browser playtest (no deployment)."""
from pathlib import Path
import unittest
import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/chronicles-autonomous-playtest.yml"


class AutonomousStagingPlaytestContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.workflow = yaml.load(cls.text, Loader=yaml.BaseLoader)

    def test_scheduled_and_manual_only_after_the_security_contracts(self):
        spec = self.workflow
        self.assertEqual(spec["permissions"], {"contents": "read"})
        self.assertEqual(spec["on"]["schedule"], [{"cron": "12 7 * * *"}])
        self.assertIn("workflow_dispatch", spec["on"])
        self.assertEqual(spec["concurrency"]["cancel-in-progress"], "false")
        playtest = spec["jobs"]["playtest"]
        self.assertEqual(playtest["needs"], "contracts")
        self.assertEqual(playtest["environment"]["name"], "staging")
        self.assertIn("github.ref == 'refs/heads/main'", playtest["if"])
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", playtest["if"])
        self.assertIn("github.event_name != 'pull_request'", playtest["if"])
        self.assertEqual(playtest["timeout-minutes"], "35")

    def test_matches_the_actual_staged_release_and_never_exposes_the_invite_to_checkout(self):
        steps = self.workflow["jobs"]["playtest"]["steps"]
        named = {step.get("name", ""): step for step in steps}
        order = list(named)
        manifest = named["Read exact live public Chronicles SHA"]
        checkout = named["Checkout playtester from the published SHA"]
        assertion = named["Require exact source revision"]
        install = named["Install isolated browser test dependencies"]
        runner = named["Play the real campaign with reproducible aggressive and cautious policies"]
        artifacts = named["Preserve bounded QA reports and browser captures"]

        for a, b in [
            (manifest, checkout), (checkout, assertion), (assertion, install),
            (install, runner), (runner, artifacts),
        ]:
            self.assertLess(steps.index(a), steps.index(b))
        self.assertIn("https://staging.chronicles.shadowops.dpdns.org/release.json", manifest["run"])
        self.assertIn("--max-redirs 0", manifest["run"])
        self.assertIn("--write-out '%{http_code}'", manifest["run"])
        self.assertIn("bytes > 0 && bytes <= 65536", manifest["run"])
        self.assertIn('[[ "$sha" =~ ^[0-9a-f]{40}$ ]]', manifest["run"])
        self.assertEqual(checkout["with"]["repository"], "evilsysadmin/chronicles-of-matthias")
        self.assertEqual(checkout["with"]["ref"], "${{ steps.public.outputs.sha }}")
        self.assertEqual(checkout["with"]["persist-credentials"], "false")
        self.assertEqual(assertion["env"]["PUBLIC_SHA"], "${{ steps.public.outputs.sha }}")
        self.assertIn("git -C chronicles-source rev-parse HEAD", assertion["run"])
        self.assertIn("npm ci --ignore-scripts", install["run"])
        self.assertIn("bash smoke/ensure-chromium.sh", install["run"])
        self.assertIn("node --check smoke/public-staging-playtest.mjs", install["run"])
        self.assertEqual(runner["env"]["CHRONICLES_SOURCE_SHA"], "${{ steps.public.outputs.sha }}")
        self.assertEqual(runner["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertIn("node smoke/public-staging-playtest.mjs", runner["run"])
        self.assertIn("CHRONICLES_STAGING_INVITE_CODE", runner["run"])
        self.assertEqual(artifacts["if"], "always()")
        self.assertIn("chronicles-playtest-report.json", artifacts["with"]["path"])
        self.assertIn("chronicles-playtest-*.png", artifacts["with"]["path"])

    def test_summary_is_bounded_and_runs_before_artifact_upload(self):
        steps = self.workflow["jobs"]["playtest"]["steps"]
        named = {step.get("name", ""): step for step in steps}
        summary = named["Summarize bounded playtest"]
        self.assertEqual(summary["if"], "always()")
        self.assertNotIn("env", summary)
        self.assertIn("GITHUB_STEP_SUMMARY", summary["run"])
        self.assertIn("262144", summary["run"])
        self.assertIn("chronicles-playtest-v1", summary["run"])
        self.assertIn("Number.isFinite", summary["run"])
        self.assertLess(steps.index(named["Play the real campaign with reproducible aggressive and cautious policies"]), steps.index(summary))
        self.assertLess(steps.index(summary), steps.index(named["Preserve bounded QA reports and browser captures"]))

    def test_never_mutates_infrastructure_or_weakens_the_existing_auth_gate(self):
        for forbidden in (
            "wrangler pages deploy", "OCI_PRIVATE_KEY", "CLOUDFLARE_API_TOKEN",
            "oci_chronicles_api_release.py", "SHADOWOPS_INFRA_ACTIONS_TOKEN",
            "repository_dispatch", "workflow_run",
            "persist-credentials: true",
        ):
            self.assertNotIn(forbidden, self.text)


if __name__ == "__main__":
    unittest.main()
