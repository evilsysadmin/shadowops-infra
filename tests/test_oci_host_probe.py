"""No OCI calls on PRs; fake a single fixed host read-only command."""
import pathlib
import sys
import unittest
from types import SimpleNamespace as NS

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "scripts"))
sys.path.insert(0, str(root / "tests"))
import oci_control_plane as cp
import oci_host_probe as hp
from test_oci_control_plane import FakeSDK, ENV


class Capture:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class HostSDK(FakeSDK):
    def __init__(self, *, lifecycle="SUCCEEDED", code=0, output=hp.HOST_READY+"\n", **kwargs):
        super().__init__(**kwargs)
        self.invocations = []
        self.lifecycle, self.code, self.output = lifecycle, code, output
        self.compute_instance_agent.models = NS(
            InstanceAgentCommandContent=Capture,
            InstanceAgentCommandSourceViaTextDetails=Capture,
            InstanceAgentCommandOutputViaTextDetails=Capture,
            CreateInstanceAgentCommandDetails=Capture,
            InstanceAgentCommandTarget=Capture,
        )
        self.compute_instance_agent.ComputeInstanceAgentClient = lambda config: self

    def create_instance_agent_command(self, **kwargs):
        self.invocations.append(("create", kwargs))
        return NS(data=NS(id="test-command"))

    def get_instance_agent_command_execution(self, **kwargs):
        self.invocations.append(("poll", kwargs))
        return NS(data=NS(lifecycle_state=self.lifecycle,
                          content=NS(exit_code=self.code, text=self.output)))


class TestFixedHostProbe(unittest.TestCase):
    def test_success_only_for_fixed_read_only_command(self):
        sdk = HostSDK()
        hp.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _:None)
        self.assertEqual(len([x for x in sdk.invocations if x[0] == "create"]), 1)
        obj = sdk.invocations[0][1]["create_instance_agent_command_details"]
        self.assertEqual(obj.kwargs["target"].kwargs["instance_id"], "instance-test")
        source = obj.kwargs["content"].kwargs["source"].kwargs["text"]
        self.assertEqual(source, hp.HOST_COMMAND)
        self.assertNotIn("sudo", source)
        self.assertNotIn("docker compose up", source)

    def test_refuse_failed_or_missing_result(self):
        for change in ({"lifecycle": "FAILED"}, {"code": 1},
                       {"output": "untrusted output\\n"},
                       {"plugin": "STOPPED"}, {"shape": "VM.Standard.E4.Flex"}):
            with self.subTest(change=change):
                sdk = HostSDK(**change)
                with self.assertRaises(cp.InventoryError):
                    hp.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _:None)
                if change.get("plugin") or change.get("shape"):
                    self.assertFalse(sdk.invocations)

    def test_reject_arbitrary_remote_command(self):
        for value in ("sudo docker ps", hp.HOST_COMMAND + "\\nsudo id",
                      "docker compose up --detach", "", "echo token"):
            with self.subTest(value=value):
                with self.assertRaises(cp.InventoryError):
                    hp.assert_command_safe(value)


if __name__ == "__main__":
    unittest.main()
