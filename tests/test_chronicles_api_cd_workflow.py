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

    def test_deployment_target_visible_in_workflow_run_title(self):
        self.assertIn('STAGING / PRODUCTION', self.workflow['name'])
        run_name = self.workflow['run-name']
        self.assertIn("github.event_name == 'pull_request'", run_name)
        self.assertIn("'CI only'", run_name)
        self.assertIn("inputs.environment == 'production'", run_name)
        self.assertIn("'PRODUCTION'", run_name)
        self.assertIn("'STAGING'", run_name)
        self.assertIn('inputs.action || github.event_name', run_name)

    def test_source_ci_and_manual_entrypoint_retained(self):
        events = self.workflow["on"]
        self.assertIn("workflow_dispatch", events)
        self.assertIn("push", events)
        self.assertIn("schedule", events)
        self.assertIn("17 * * * *", [row["cron"] for row in events["schedule"]])
        self.assertIn("provision", events["workflow_dispatch"]["inputs"]["action"]["options"])
        self.assertIn("deploy", events["workflow_dispatch"]["inputs"]["action"]["options"])

    def test_every_infra_main_push_reconciles_even_for_unrelated_changes(self):
        events = self.workflow["on"]
        self.assertEqual(events["push"]["branches"], ["main"])
        self.assertNotIn("paths", events["push"])
        # Keep PR contracts selective: the broad push must not explode PR CI.
        self.assertIn("paths", events["pull_request"])
        # The candidate gate is still fail-closed and receipt/idempotency aware.
        selection = next(step["run"] for step in self.workflow["jobs"]["admit"]["steps"]
                         if step.get("id") == "candidate")
        self.assertIn("chronicles_source_ci.py", selection)
        self.assertIn("--receipt-only", selection)
        self.assertIn("deploy_needed=false", selection)

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
        self.assertEqual(next(step['id'] for step in steps if step.get('name') == guard),
                         'staging_freshness')
        self.assertIn('CHRONICLES_OCI_STALE_SOURCE_SKIPPED', code)
        self.assertIn("fresh=false' >> \"$GITHUB_OUTPUT\"", code)
        self.assertIn("fresh=true' >> \"$GITHUB_OUTPUT\"", code)
        self.assertIn('CHRONICLES_OCI_INVALID_SOURCE', code)
        self.assertEqual(
            next(step["if"] for step in steps if step.get("name") == guard),
            "inputs.environment != 'production' && steps.staging_preflight.outputs.fresh == 'true'")

    def test_staging_preflight_saves_sdk_setup_and_keeps_second_guard(self):
        steps = self.workflow['jobs']['deploy']['steps']
        preflight = next(s for s in steps if s.get('id') == 'staging_preflight')
        late = next(s for s in steps if s.get('id') == 'staging_freshness')
        self.assertEqual(preflight['if'], "inputs.environment != 'production'")
        self.assertLess(steps.index(preflight),
                        next(i for i, s in enumerate(steps) if s.get('uses') == 'actions/setup-python@v5'))
        self.assertLess(steps.index(preflight), steps.index(late))
        self.assertIn('commits/main', preflight['run'])
        self.assertIn('CHRONICLES_OCI_STALE_SOURCE_PRECHECK_SKIPPED', preflight['run'])
        self.assertIn('CHRONICLES_OCI_INVALID_MAIN_SHA', preflight['run'])
        self.assertIn('CHRONICLES_OCI_INVALID_MAIN_SHA', late['run'])

    def test_preflight_rejects_unverifiable_main_and_skips_stale(self):
        guard = next(s for s in self.workflow['jobs']['deploy']['steps']
                     if s.get('id') == 'staging_preflight')
        sha = 'a' * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / 'gh'
            gh.write_text('#!/bin/sh\n'
                          'if [ "$FAKE_GH_FAIL" = true ]; then exit 7; fi\n'
                          'printf "%s\\n" "$FAKE_MAIN_SHA"\n')
            gh.chmod(0o755)
            for admitted, main_sha, failure, code, flag in (
                (sha, sha, 'false', 0, 'fresh=true'),
                (sha, 'b' * 40, 'false', 0, 'fresh=false'),
                (sha, 'invalid', 'false', 65, ''),
                (sha, sha, 'true', 7, ''),
                ('invalid', sha, 'false', 64, ''),
            ):
                with self.subTest(admitted=admitted, main=main_sha, failure=failure):
                    output = root / 'output'
                    summary = root / 'summary'
                    output.write_text('')
                    summary.write_text('')
                    env = dict(os.environ, PATH=f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                               ADMITTED_SHA=admitted, GH_TOKEN='test-only',
                               FAKE_MAIN_SHA=main_sha, FAKE_GH_FAIL=failure,
                               GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary))
                    run = subprocess.run(['bash', '-c', guard['run']],
                                         env=env, capture_output=True, text=True, check=False)
                    self.assertEqual(run.returncode, code, run.stderr)
                    self.assertEqual(output.read_text().strip(), flag)
                    if flag == 'fresh=false':
                        self.assertIn('PRECHECK_SKIPPED', run.stdout)
                        self.assertIn('SDK', summary.read_text())

    def test_superseded_staging_gates_all_mutations_smokes_and_receipts(self):
        steps = self.workflow['jobs']['deploy']['steps']
        by_name = {step.get('name'): step for step in steps}
        fresh = "steps.staging_freshness.outputs.fresh == 'true'"
        for name in (
            'Execute only the restricted Chronicles API deployer',
            'Public smoke through the Chronicles tunnel',
            'Prove public staging API serves the admitted source SHA',
            'Player-path smoke (register, run, save, reload; account always deleted)',
            'Record successfully verified staging generation',
            'Publish verified generation receipt (idempotent future sync)',
        ):
            with self.subTest(step=name):
                self.assertIn(fresh, by_name[name]['if'])
        for name in (
            'Execute only the restricted Chronicles API deployer',
            'Public smoke through the Chronicles tunnel',
        ):
            self.assertIn("inputs.environment == 'production'", by_name[name]['if'])
        for name in (
            'Require verified staging API and Pages before production mutation',
            'Record successfully verified production API generation',
            'Save verified production API receipt for Pages promotion',
        ):
            self.assertEqual(by_name[name]['if'], "inputs.environment == 'production'")

    def test_staging_freshness_guard_exits_clean_only_for_superseded_shas(self):
        steps = self.workflow['jobs']['deploy']['steps']
        guard = next(s for s in steps if s.get('id') == 'staging_freshness')
        sha = 'a' * 40
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            gh = path / 'gh'
            gh.write_text('#!/bin/sh\n'
                          'if [ "$FAKE_GH_FAIL" = true ]; then exit 7; fi\n'
                          'printf "%s\\n" "$FAKE_MAIN_SHA"\n')
            gh.chmod(0o755)
            for main_sha, gh_fail, expected_code, expected_fresh in (
                (sha, 'false', 0, 'fresh=true'),
                ('b' * 40, 'false', 0, 'fresh=false'),
                (sha, 'true', 7, None),
                ('not-a-valid-sha', 'false', 65, None),
            ):
                output, summary = path / 'output', path / 'summary'
                output.write_text('')
                summary.write_text('')
                env = dict(os.environ,
                           PATH=f"{path}{os.pathsep}{os.environ.get('PATH', '')}",
                           ADMITTED_SHA=sha, GH_TOKEN='test-only',
                           FAKE_MAIN_SHA=main_sha, FAKE_GH_FAIL=gh_fail,
                           GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary))
                result = subprocess.run(['bash', '-c', guard['run']],
                                        env=env, capture_output=True, text=True, check=False)
                with self.subTest(main_sha=main_sha, gh_fail=gh_fail):
                    self.assertEqual(result.returncode, expected_code, result.stderr)
                    self.assertEqual(output.read_text().strip(), expected_fresh or '')
                    if expected_fresh == 'fresh=false':
                        self.assertIn('STALE_SOURCE_SKIPPED', result.stdout)
                        self.assertIn('skipped', summary.read_text())
            output.write_text('')
            env['ADMITTED_SHA'] = 'invalid'
            env['FAKE_GH_FAIL'] = 'false'
            result = subprocess.run(['bash', '-c', guard['run']],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(output.read_text(), '')

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
        self.assertEqual(revision["if"], "inputs.environment != 'production' && steps.staging_freshness.outputs.fresh == 'true'")
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
        gate = "inputs.environment == 'production' || steps.staging_preflight.outputs.fresh == 'true'"
        self.assertEqual(install["if"], gate)
        self.assertEqual(cache["if"], gate)
        setup = next(step for step in steps if step.get("uses") == "actions/setup-python@v5")
        self.assertEqual(setup["if"], gate)
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
