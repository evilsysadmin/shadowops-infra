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

    def test_central_admin_requires_manual_staging_provision_and_private_secret(self):
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["central_admin"]["options"], ["preserve", "enable", "disable"])
        self.assertEqual(inputs["central_admin"]["default"], "preserve")
        provision_job = self.workflow["jobs"]["provision"]
        self.assertIn("workflow_dispatch", provision_job["if"])
        self.assertIn("inputs.action == 'provision'", provision_job["if"])
        values = provision_job["env"]
        self.assertIn("inputs.central_admin || 'preserve'", values["CHRONICLES_CENTRAL_ADMIN"])
        self.assertIn("secrets.CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE",
                      values["CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE"])
        self.assertNotIn("CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE",
                         self.workflow["jobs"]["deploy"].get("env", {}))

    def test_single_dispatch_admin_grant_provisions_then_deploys_only_in_staging(self):
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["action"]["options"], ["provision", "deploy", "grant-admin"])
        provision = self.workflow["jobs"]["provision"]
        self.assertIn("inputs.action == 'provision'", provision["if"])
        self.assertIn("inputs.action == 'grant-admin' && inputs.environment == 'staging'", provision["if"])
        self.assertIn("refs/heads/main", provision["if"])
        self.assertIn("evilsysadmin/shadowops-infra", provision["if"])
        self.assertEqual(provision["environment"]["name"], "${{ inputs.environment }}")
        self.assertIn("inputs.action == 'grant-admin' && 'enable'",
                      provision["env"]["CHRONICLES_CENTRAL_ADMIN"])
        self.assertIn("inputs.central_admin || 'preserve'",
                      provision["env"]["CHRONICLES_CENTRAL_ADMIN"])
        self.assertIn("secrets.CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE",
                      provision["env"]["CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE"])
        guard = next(step for step in provision["steps"]
                     if step.get("name") == "Require current root-owned OCI wrapper before granting central admin")
        self.assertIn("inputs.action == 'grant-admin'", guard["if"])
        self.assertLess(provision["steps"].index(guard),
                        next(i for i, step in enumerate(provision["steps"]
                                                       ) if step.get("name", "").startswith("Provision (")))

        admit = self.workflow["jobs"]["admit"]
        self.assertEqual(admit["needs"], ["contracts", "provision"])
        self.assertIn("always()", admit["if"])
        self.assertIn("needs.contracts.result == 'success'", admit["if"])
        self.assertIn("inputs.action == 'grant-admin' && inputs.environment == 'staging'", admit["if"])
        self.assertIn("needs.provision.result == 'success'", admit["if"])
        self.assertIn("inputs.action == 'deploy'", admit["if"])
        self.assertIn("github.event_name == 'schedule'", admit["if"])
        self.assertIn("github.event_name == 'push'", admit["if"])
        self.assertIn("refs/heads/main", admit["if"])
        self.assertIn("evilsysadmin/shadowops-infra", admit["if"])
        self.assertEqual(self.workflow["jobs"]["deploy"]["needs"], "admit")
        self.assertIn("needs.admit.outputs.deploy_needed", self.workflow["jobs"]["deploy"]["if"])
        self.assertNotIn("CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE",
                         self.workflow["jobs"]["deploy"].get("env", {}))

    def test_admin_grant_production_is_a_hard_failure_not_a_skipped_success(self):
        contracts = self.workflow["jobs"]["contracts"]
        guard = next(step for step in contracts["steps"]
                     if step.get("name") == "Reject administrative grant outside staging")
        self.assertEqual(
            guard["if"],
            "github.event_name == 'workflow_dispatch' && inputs.action == 'grant-admin' && inputs.environment != 'staging'")
        self.assertIn("CHRONICLES_ADMIN_GRANT_BLOCKED staging-only", guard["run"])
        self.assertIn("exit 65", guard["run"])
        self.assertLess(contracts["steps"].index(guard), next(
            i for i, step in enumerate(contracts["steps"])
            if "test_chronicles_api_host_deploy.py" in str(step.get("run", ""))))

    def test_admin_grant_forces_redeploy_and_disallows_silent_stale_skip(self):
        admit = self.workflow["jobs"]["admit"]
        self.assertIn("inputs.action == 'grant-admin' && 'false'",
                      admit["env"]["ONLY_IF_NEW"])
        selection = next(step["run"] for step in admit["steps"]
                         if step.get("id") == "candidate")
        self.assertIn('GITHUB_EVENT_NAME', selection)
        self.assertIn("ONLY_IF_NEW", selection)
        deploy = self.workflow["jobs"]["deploy"]
        preflight = next(step for step in deploy["steps"]
                         if step.get("id") == "staging_preflight")
        late = next(step for step in deploy["steps"]
                    if step.get("id") == "staging_freshness")
        for guard in (preflight, late):
            self.assertEqual(guard["env"]["GRANT_ADMIN"], "${{ inputs.action == 'grant-admin' }}")
            self.assertIn('if [[ "${GRANT_ADMIN:-false}" == \'true\' ]]; then', guard["run"])
            self.assertIn("CHRONICLES_ADMIN_GRANT_DEPLOY_BLOCKED", guard["run"])
            self.assertIn("exit 65", guard["run"])
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_PRECHECK_SKIPPED", preflight["run"])
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_SKIPPED", late["run"])

    def test_grant_admin_stale_source_fails_before_any_deployment(self):
        steps = self.workflow["jobs"]["deploy"]["steps"]
        guards = [next(step["run"] for step in steps if step.get("id") == guard_id)
                  for guard_id in ("staging_preflight", "staging_freshness")]
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / "gh"
            gh.write_text('#!/bin/sh\n'
                          'printf "%s\\n" "$FAKE_MAIN_SHA"\n')
            gh.chmod(0o755)
            for guard in guards:
                for grant_admin, expected_code, expected_output in (
                    ("true", 65, ""),
                    ("false", 0, "fresh=false"),
                ):
                    with self.subTest(grant_admin=grant_admin, guard=guard[:40]):
                        output = root / "output"
                        summary = root / "summary"
                        output.write_text("")
                        summary.write_text("")
                        env = dict(os.environ,
                                   PATH=f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                                   GRANT_ADMIN=grant_admin, ADMITTED_SHA=sha,
                                   FAKE_MAIN_SHA="b" * 40,
                                   GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary))
                        result = subprocess.run(["bash", "-c", guard], env=env,
                                                capture_output=True, text=True, check=False)
                        self.assertEqual(result.returncode, expected_code, result.stderr)
                        self.assertEqual(output.read_text().strip(), expected_output)
                        if grant_admin == "true":
                            self.assertIn("CHRONICLES_ADMIN_GRANT_DEPLOY_BLOCKED", result.stderr)
                            self.assertNotIn("SKIPPED", result.stdout)
                        else:
                            self.assertIn("STALE_SOURCE", result.stdout)

    def test_admin_grant_checks_live_installed_wrapper_before_any_cloud_mutation(self):
        provision = self.workflow["jobs"]["provision"]
        steps = provision["steps"]
        by_name = {step.get("name"): step for step in steps}
        guard = "Require current root-owned OCI wrapper before granting central admin"
        update = "Provision (never prints secrets, tokens, IDs or DNS targets)"
        self.assertIn(guard, by_name)
        self.assertLess(steps.index(by_name[guard]), steps.index(by_name[update]))
        self.assertEqual(by_name[guard]["if"],
                         "inputs.environment == 'staging' && (inputs.central_admin == 'enable' || inputs.action == 'grant-admin')")
        command = by_name[guard]["run"]
        self.assertEqual(by_name[guard]["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertIn("scripts/oci_host_probe.py wrapper", command)
        self.assertEqual(command.count("gh api repos/evilsysadmin/shadowops-infra/commits/main"), 2)
        self.assertIn("CHRONICLES_API_WRAPPER_CURRENT", command)
        self.assertIn("CHRONICLES_ADMIN_GRANT_WRAPPER_READY", command)
        self.assertIn("set -euo pipefail", command)
        self.assertNotIn("ADMIN_USERNAMES", command)
        self.assertNotIn("CHRONICLES_STAGING_CENTRAL_ADMIN_PROFILE", command)

    def test_admin_grant_wrapper_gate_rejects_bad_verdict_and_main_drift(self):
        command = next(step["run"] for step in self.workflow["jobs"]["provision"]["steps"]
                       if step.get("name") == "Require current root-owned OCI wrapper before granting central admin")
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / "gh"
            gh.write_text("""#!/bin/sh
count=0
if [ -f "$GH_COUNTER" ]; then count=$(cat "$GH_COUNTER"); fi
count=$((count+1))
printf '%s' "$count" > "$GH_COUNTER"
if [ "$count" -eq 1 ]; then
  printf '%s' "$FAKE_BEFORE"
else
  printf '%s' "$FAKE_AFTER"
fi
""")
            gh.chmod(0o755)
            python = root / "python"
            python.write_text("""#!/bin/sh
if [ "$1" != scripts/oci_host_probe.py ] || [ "$2" != wrapper ]; then exit 99; fi
printf '%s' "$FAKE_VERDICT"
exit "${FAKE_PROBE_EXIT:-0}"
""")
            python.chmod(0o755)
            for before, verdict, after, exit_code, accepted in (
                (sha, "CHRONICLES_API_WRAPPER_CURRENT", sha, "0", True),
                ("b" * 40, "CHRONICLES_API_WRAPPER_CURRENT", sha, "0", False),
                (sha, "CHRONICLES_API_WRAPPER_OUTDATED", sha, "1", False),
                (sha, "CHRONICLES_API_WRAPPER_MISSING", sha, "1", False),
                (sha, "CHRONICLES_API_WRAPPER_UNSAFE", sha, "1", False),
                (sha, "CHRONICLES_API_WRAPPER_CURRENT", "b" * 40, "0", False),
                (sha, "CHRONICLES_API_WRAPPER_CURRENT", sha, "1", False),
                (sha, "bogus\nCHRONICLES_API_WRAPPER_CURRENT", sha, "0", False),
            ):
                with self.subTest(before=before, verdict=verdict, after=after, exit_code=exit_code):
                    counter = root / "counter"
                    counter.unlink(missing_ok=True)
                    env = dict(os.environ,
                               PATH=f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                               GITHUB_SHA=sha, GH_COUNTER=str(counter),
                               FAKE_BEFORE=before, FAKE_VERDICT=verdict,
                               FAKE_AFTER=after, FAKE_PROBE_EXIT=exit_code)
                    result = subprocess.run(["bash", "-c", command], env=env,
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode == 0, accepted,
                                     result.stdout + result.stderr)
                    self.assertEqual(
                        "CHRONICLES_ADMIN_GRANT_WRAPPER_READY" in result.stdout,
                        accepted,
                    )

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
