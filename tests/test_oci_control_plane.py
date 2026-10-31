"""Read-only OCI custody inventory contracts without actual OCI credentials."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace as NS
from contextlib import redirect_stdout
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import oci_control_plane as cp

class FakeSDK:
    def __init__(self, *, compartments=None, instances=None, shape=cp.SHAPE, plugin="RUNNING"):
        self.observed = []
        self.config = NS(validate_config=lambda config: self.observed.append(("validate", config["region"])))
        self.identity = NS(IdentityClient=lambda config: NS(list_compartments=lambda *args, **kwargs: None))
        self.core = NS(ComputeClient=lambda config: NS(list_instances=lambda *args, **kwargs: None))
        self.retry = NS(DEFAULT_RETRY_STRATEGY=object())
        self.compute_instance_agent = NS(PluginClient=lambda config: NS(
            get_instance_agent_plugin=self._get_plugin))
        self._plugin = plugin
        self._compartments = compartments if compartments is not None else [NS(name=cp.COMPARTMENT, id="compartment-test")]
        self._instances = instances if instances is not None else [
            NS(display_name=cp.INSTANCE, id="instance-test", lifecycle_state="RUNNING", shape=shape)
        ]
        self.pagination = NS(list_call_get_all_results=self._paginate)

    def _paginate(self, func, *args, **kwargs):
        self.observed.append(("list", kwargs))
        if "access_level" in kwargs:
            return NS(data=self._compartments)
        return NS(data=self._instances)

    def _get_plugin(self, **kwargs):
        self.observed.append(("plugin", kwargs))
        return NS(data=NS(status=self._plugin))

ENV = {
    "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..TEST",
    "OCI_USER_OCID": "ocid1.user.oc1..TEST",
    "OCI_FINGERPRINT": "aa:bb:cc",
    "OCI_PRIVATE_KEY": "-----BEGIN TEST KEY-----",
}

class TestOCIInventory(unittest.TestCase):
    def test_reads_one_fixed_running_a1_and_healthy_plugin(self):
        sdk = FakeSDK()
        config = cp.config_from_env(sdk, ENV)
        report = cp.inspect(sdk, config)
        self.assertEqual(report["instance"], cp.INSTANCE)
        self.assertEqual(report["run_command"], "RUNNING")
        self.assertEqual(sdk.observed[1][1]["name"], cp.COMPARTMENT)
        self.assertEqual(sdk.observed[2][1]["display_name"], cp.INSTANCE)
        self.assertEqual(sdk.observed[3][1]["plugin_name"], cp.PLUGIN)
        self.assertEqual(len([x for x in sdk.observed if x[0] == "plugin"]), 1)

    def test_verified_release_host_uses_one_inventory_and_one_plugin_probe(self):
        sdk = FakeSDK()
        config = cp.config_from_env(sdk, ENV)
        result = cp.verified_run_command_host(sdk, config)
        self.assertEqual(result, ("compartment-test", "instance-test"))
        self.assertEqual([name for name, _ in sdk.observed],
                         ["validate", "list", "list", "plugin"])

    def test_release_executes_on_prevalidated_host_without_second_inventory(self):
        from unittest.mock import patch
        import oci_chronicles_api_release as release

        sdk = FakeSDK()
        config = cp.config_from_env(sdk, ENV)
        digest = "sha256:" + "a" * 64
        vault = "ocid1.vault.oc1.eu-frankfurt-1.abcdefghijkl"
        marker = release.marker_for("staging") + digest
        timing = ("CHRONICLES_API_OCI_HOST_PHASE_SECONDS guard=2 vault=3 runtime=4 "
                  "compose=5 pull=16 recheck=4 up=36 smoke=5 receipt=1")
        commands = []

        class Agent:
            def create_instance_agent_command(self, **kwargs):
                commands.append(kwargs)
                return NS(data=NS(id="command-test"))

            def get_instance_agent_command_execution(self, **kwargs):
                commands.append(kwargs)
                return NS(data=NS(lifecycle_state="SUCCEEDED",
                                  content=NS(text="SECRET_INTERNAL_LOG\n" + timing + "\n" + marker + "\n",
                                             exit_code=0)))

        sdk.compute_instance_agent.models = NS(
            InstanceAgentCommandSourceViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandOutputViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandContent=lambda **kw: NS(**kw),
            InstanceAgentCommandTarget=lambda **kw: NS(**kw),
            CreateInstanceAgentCommandDetails=lambda **kw: NS(**kw),
        )
        sdk.compute_instance_agent.ComputeInstanceAgentClient = lambda cfg: Agent()
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "actions.md"
            with patch("chronicles_api_provision.resolve_vault",
                       return_value=(vault, None, None)), patch.dict(
                           os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), redirect_stdout(stdout):
                actual = release.execute(sdk, config, digest, pause=lambda _: None,
                                         clock=lambda: 100.0)
            summary_text = summary.read_text()
        self.assertIn("Verified wrapper smoke: yes", summary_text)
        self.assertIn(timing, summary_text)
        self.assertIn("not observed; no queue/active split inferred", summary_text)
        self.assertNotIn("SECRET_INTERNAL_LOG", summary_text)
        self.assertNotIn(vault, summary_text)
        self.assertEqual(actual, marker)
        self.assertIn(timing + "\n", stdout.getvalue())
        self.assertNotIn("SECRET_INTERNAL_LOG", stdout.getvalue())
        self.assertEqual(stdout.getvalue().splitlines()[-1], marker)
        self.assertEqual([name for name, _ in sdk.observed],
                         ["validate", "list", "list", "plugin"])
        self.assertEqual(len(commands), 2, "Only one create and one poll allowed")
        self.assertEqual(commands[0]["create_instance_agent_command_details"].target.instance_id,
                         "instance-test")
        self.assertEqual(commands[1]["instance_id"], "instance-test")


    def test_oci_lifecycle_timing_is_observation_not_guessed_host_runtime(self):
        import oci_chronicles_api_release as release
        self.assertEqual(release.observed_lifecycle_timing(2, 7, 16),
                         "CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=5 active=9")
        self.assertEqual(release.observed_lifecycle_timing(2, None, 16), "")
        self.assertEqual(release.observed_lifecycle_timing(10, 8, 5),
                         "CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=0 active=0")
        self.assertEqual(release.observed_lifecycle_timing(0, 500000, 1000000),
                         "CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=99999 active=99999")

    def test_release_measures_observed_in_progress_without_raw_remote_logs(self):
        from unittest.mock import patch
        import oci_chronicles_api_release as release
        sdk = FakeSDK()
        config = cp.config_from_env(sdk, ENV)
        digest = "sha256:" + "a" * 64
        vault = "ocid1.vault.oc1.eu-frankfurt-1.abcdefghijkl"
        marker = release.marker_for("staging") + digest

        class Agent:
            def __init__(self, end_state):
                self.states = ["ACCEPTED", "IN_PROGRESS", end_state]
                self.end_state = end_state

            def create_instance_agent_command(self, **kwargs):
                return NS(data=NS(id="command-test"))

            def get_instance_agent_command_execution(self, **kwargs):
                status = self.states.pop(0)
                return NS(data=NS(lifecycle_state=status, content=NS(
                    text="SECRET_REMOTE_LOG\n" + marker if status == "SUCCEEDED"
                    else "SECRET_REMOTE_LOG", exit_code=0 if status == "SUCCEEDED" else 1)))

        sdk.compute_instance_agent.models = NS(
            InstanceAgentCommandSourceViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandOutputViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandContent=lambda **kw: NS(**kw),
            InstanceAgentCommandTarget=lambda **kw: NS(**kw),
            CreateInstanceAgentCommandDetails=lambda **kw: NS(**kw),
        )
        for final_status in ("SUCCEEDED", "FAILED"):
            with self.subTest(status=final_status):
                agent = Agent(final_status)
                sdk.compute_instance_agent.ComputeInstanceAgentClient = lambda cfg: agent
                clock = iter((0, 1, 2, 3, 4, 7, 8, 16))
                output = io.StringIO()
                with tempfile.TemporaryDirectory() as tmp:
                    report = Path(tmp) / "summary.md"
                    with patch("chronicles_api_provision.resolve_vault",
                               return_value=(vault, None, None)), patch.dict(
                                   os.environ, {"GITHUB_STEP_SUMMARY": str(report)}), redirect_stdout(output):
                        if final_status == "SUCCEEDED":
                            self.assertEqual(release.execute(sdk, config, digest,
                                              pause=lambda _: None, clock=lambda: next(clock)), marker)
                        else:
                            with self.assertRaises(cp.InventoryError):
                                release.execute(sdk, config, digest,
                                                pause=lambda _: None, clock=lambda: next(clock))
                    summary = report.read_text()
                self.assertIn("Verified wrapper smoke: " + (
                    "yes" if final_status == "SUCCEEDED" else "no"), summary)
                self.assertIn("pre_active=5 active=9", summary)
                self.assertNotIn("SECRET_REMOTE_LOG", summary)
                self.assertNotIn(vault, summary)
                lines = output.getvalue().splitlines()
                self.assertIn("CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=5 active=9", lines)
                self.assertIn("CHRONICLES_API_OCI_PHASE_SECONDS preflight=1 dispatch=1 execution=14", lines)
                self.assertNotIn("SECRET_REMOTE_LOG", output.getvalue())
                self.assertNotIn(vault, output.getvalue())
                self.assertEqual(lines[-1] == marker, final_status == "SUCCEEDED")

    def test_actions_summary_only_renders_allowlisted_timing(self):
        import oci_chronicles_api_release as release
        phase = "CHRONICLES_API_OCI_PHASE_SECONDS preflight=7 dispatch=0 execution=213"
        lifecycle = ("CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS "
                     "pre_active=10 active=203")
        host = ("CHRONICLES_API_OCI_HOST_PHASE_SECONDS guard=2 vault=3 runtime=4 "
                "compose=5 pull=16 recheck=4 up=36 smoke=5 receipt=1")
        good = release.timing_summary(phase, lifecycle, host, verified=True)
        self.assertIn("Verified wrapper smoke: yes", good)
        self.assertIn(phase, good)
        self.assertIn(lifecycle, good)
        self.assertIn(host, good)
        self.assertNotIn("sha256:", good)
        self.assertNotIn("ocid1.", good)
        missing = release.timing_summary(phase, verified=False)
        self.assertIn("Verified wrapper smoke: no", missing)
        self.assertIn("not observed; no queue/active split inferred", missing)
        self.assertIn("does not prove the wrapper is outdated", missing)
        for untrusted in ("SECRET\n" + phase, phase + " SECRET", phase + "\nextra",
                          phase.replace("execution=213", "execution=-213"),
                          phase.replace("execution=213", "execution=123456")):
            with self.subTest(untrusted=untrusted[:35]):
                self.assertEqual(release.timing_summary(untrusted, verified=True), "")
        self.assertEqual(release.timing_summary(phase, "SECRET\n" + lifecycle,
                                                verified=True), "")
        self.assertEqual(release.timing_summary(phase, lifecycle, host + " SECRET",
                                                verified=True), "")
        with tempfile.TemporaryDirectory() as tmp:
            destination = str(Path(tmp) / "github-summary.md")
            release.append_timing_summary(phase, lifecycle, host,
                                          verified=True, path=destination)
            release.append_timing_summary("secret\n" + phase, verified=True,
                                          path=destination)
            self.assertEqual(Path(destination).read_text(), good)
            release.append_timing_summary(phase, verified=True,
                                          path=str(Path(tmp) / "missing" / "file"))
            self.assertEqual(Path(destination).read_text(), good)

    def test_oci_nonterminal_timeout_reports_unverified_timings_without_secrets(self):
        from unittest.mock import patch
        import oci_chronicles_api_release as release

        sdk = FakeSDK()
        digest = "sha256:" + "a" * 64
        vault = "ocid1.vault.oc1.eu-frankfurt-1.abcdefghijkl"
        sdk.compute_instance_agent.models = NS(
            InstanceAgentCommandSourceViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandOutputViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandContent=lambda **kw: NS(**kw),
            InstanceAgentCommandTarget=lambda **kw: NS(**kw),
            CreateInstanceAgentCommandDetails=lambda **kw: NS(**kw),
        )
        for name, statuses, ticks, lifecycle in (
            ("observed-active", ["ACCEPTED", "IN_PROGRESS"],
             (0, 1, 2, 3, 4, 5, 652, 653),
             "CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS pre_active=3 active=648"),
            ("unobserved-active", ["ACCEPTED"],
             (0, 1, 2, 3, 652, 653), ""),
        ):
            with self.subTest(scenario=name):
                class Agent:
                    def __init__(self):
                        self.polled = 0
                        self.created = 0

                    def create_instance_agent_command(self, **kwargs):
                        self.created += 1
                        return NS(data=NS(id="command-test"))

                    def get_instance_agent_command_execution(self, **kwargs):
                        status = statuses[self.polled]
                        self.polled += 1
                        return NS(data=NS(lifecycle_state=status,
                                          content=NS(text="SECRET_REMOTE_LOG", exit_code=0)))

                agent = Agent()
                sdk.compute_instance_agent.ComputeInstanceAgentClient = lambda cfg: agent
                iterator = iter(ticks)
                output = io.StringIO()
                with tempfile.TemporaryDirectory() as tmp:
                    summary = Path(tmp) / "actions.md"
                    with patch("chronicles_api_provision.resolve_vault",
                               return_value=(vault, None, None)), patch.dict(
                                   os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), redirect_stdout(output):
                        with self.assertRaisesRegex(cp.InventoryError, "timed out"):
                            release.execute(sdk, cp.config_from_env(sdk, ENV), digest,
                                            pause=lambda _: None, clock=lambda: next(iterator))
                    report = summary.read_text()
                phase = "CHRONICLES_API_OCI_PHASE_SECONDS preflight=1 dispatch=1 execution=651"
                self.assertIn(phase, output.getvalue())
                self.assertIn(phase, report)
                self.assertIn("Verified wrapper smoke: no", report)
                self.assertIn("not reported", report)
                self.assertNotIn(release.marker_for("staging"), report + output.getvalue())
                self.assertNotIn("SECRET_REMOTE_LOG", report + output.getvalue())
                self.assertNotIn(vault, report + output.getvalue())
                if lifecycle:
                    self.assertIn(lifecycle, report)
                    self.assertIn(lifecycle, output.getvalue())
                else:
                    self.assertIn("not observed; no queue/active split inferred", report)
                    self.assertNotIn("CHRONICLES_API_OCI_LIFECYCLE_OBSERVED_SECONDS",
                                     output.getvalue())
                self.assertEqual(agent.created, 1)
                self.assertEqual(agent.polled, len(statuses))
                self.assertEqual(next(iterator, None), None)

    def test_release_rejects_unhealthy_plugin_before_submitting_any_command(self):
        from unittest.mock import patch
        import oci_chronicles_api_release as release

        sdk = FakeSDK(plugin="STOPPED")
        sdk.compute_instance_agent.ComputeInstanceAgentClient = lambda cfg: self.fail(
            "No Run Command client when plugin admission fails")
        with patch("chronicles_api_provision.resolve_vault", return_value=(
            "ocid1.vault.oc1.eu-frankfurt-1.abcdefghijkl", None, None)):
            with self.assertRaises(cp.InventoryError):
                release.execute(sdk, cp.config_from_env(sdk, ENV), "sha256:" + "a" * 64)
        self.assertEqual([name for name, _ in sdk.observed],
                         ["validate", "list", "list", "plugin"])

    def test_oci_only_exposes_verified_host_timings_after_success(self):
        import oci_chronicles_api_release as release
        sample = ("CHRONICLES_API_OCI_HOST_PHASE_SECONDS guard=2 vault=3 runtime=4 "
                  "compose=5 pull=16 recheck=4 up=36 smoke=5 receipt=1")
        self.assertEqual(release.trusted_host_timing("secret line\n" + sample + "\n"),
                         sample)
        for body in (
            "secret line\n",
            sample + "\n" + sample,
            sample + " VAULT_ID=sensitive",
            sample.replace("pull=16", "pull=-16"),
            sample.replace("pull=16", "pull=012"),
            sample.replace("pull=16", "pull=100000"),
            sample.replace("receipt=1", "receipt=1 SECRET=abc"),
        ):
            with self.subTest(body=body[:40]):
                self.assertEqual(release.trusted_host_timing(body), "")

    def test_missing_credential_never_calls_sdk(self):
        sdk = FakeSDK()
        for key in ENV:
            with self.subTest(key=key):
                with self.assertRaises(cp.InventoryError):
                    cp.config_from_env(sdk, {k:v for k,v in ENV.items() if k != key})
        self.assertFalse(sdk.observed)

    def test_ambiguous_or_missing_identity_fails_closed(self):
        for override in (
            {"compartments": []},
            {"compartments": [NS(name=cp.COMPARTMENT, id="a"), NS(name=cp.COMPARTMENT, id="b")]},
            {"instances": []},
            {"instances": [NS(display_name=cp.INSTANCE, id="a", shape=cp.SHAPE, lifecycle_state="RUNNING"),
                           NS(display_name=cp.INSTANCE, id="b", shape=cp.SHAPE, lifecycle_state="RUNNING")]},
            {"shape": "VM.Standard.E4.Flex"},
            {"plugin": "STOPPED"},
        ):
            with self.subTest(override=override):
                sdk = FakeSDK(**override)
                with self.assertRaises(cp.InventoryError):
                    cp.inspect(sdk, cp.config_from_env(sdk, ENV))

    def test_scripts_have_no_oci_mutation_or_secret_output(self):
        body = Path(cp.__file__).read_text()
        for forbidden in ("instance_action(", "create_instance_agent_command(", "put_object(",
                          "delete_", "terraform apply", "subprocess.run(", "key_content={", "print(config)"):
            self.assertNotIn(forbidden, body)

if __name__ == "__main__":
    unittest.main()
