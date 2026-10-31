"""Read-only OCI custody inventory contracts without actual OCI credentials."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace as NS
import os
import sys
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
        commands = []

        class Agent:
            def create_instance_agent_command(self, **kwargs):
                commands.append(kwargs)
                return NS(data=NS(id="command-test"))

            def get_instance_agent_command_execution(self, **kwargs):
                commands.append(kwargs)
                return NS(data=NS(lifecycle_state="SUCCEEDED",
                                  content=NS(text=marker + "\n", exit_code=0)))

        sdk.compute_instance_agent.models = NS(
            InstanceAgentCommandSourceViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandOutputViaTextDetails=lambda **kw: NS(**kw),
            InstanceAgentCommandContent=lambda **kw: NS(**kw),
            InstanceAgentCommandTarget=lambda **kw: NS(**kw),
            CreateInstanceAgentCommandDetails=lambda **kw: NS(**kw),
        )
        sdk.compute_instance_agent.ComputeInstanceAgentClient = lambda cfg: Agent()
        with patch("chronicles_api_provision.resolve_vault",
                   return_value=(vault, None, None)):
            actual = release.execute(sdk, config, digest, pause=lambda _: None,
                                     clock=lambda: 100.0)
        self.assertEqual(actual, marker)
        self.assertEqual([name for name, _ in sdk.observed],
                         ["validate", "list", "list", "plugin"])
        self.assertEqual(len(commands), 2, "Only one create and one poll allowed")
        self.assertEqual(commands[0]["create_instance_agent_command_details"].target.instance_id,
                         "instance-test")
        self.assertEqual(commands[1]["instance_id"], "instance-test")

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
