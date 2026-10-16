"""Fixed capability probe only; fake OCI calls in PRs."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import oci_control_plane as cp
import oci_chronicles_boot_capability as capability
from test_oci_host_probe import HostSDK, ENV


class CapabilityTests(unittest.TestCase):
    def test_one_exact_nonprivileged_command(self):
        sdk = HostSDK(output=capability.PREFIX + " docker=no repo=no wrapper=no gh=no\\n")
        output = capability.run(sdk, cp.config_from_env(sdk, ENV), pause=lambda _: None)
        self.assertEqual(output, capability.PREFIX + " docker=no repo=no wrapper=no gh=no")
        command = sdk.invocations[0][1]["create_instance_agent_command_details"]
        self.assertEqual(command.kwargs["target"].kwargs["instance_id"], "instance-test")
        self.assertEqual(command.kwargs["content"].kwargs["source"].kwargs["text"], capability.COMMAND)
        self.assertNotIn("sudo ", capability.COMMAND)

    def test_all_failures_are_fail_closed(self):
        for options in (
            {"output": "sensitive output\\n"},
            {"output": capability.PREFIX + " docker=yes repo=no wrapper=no gh=no\\nsecret"},
            {"output": capability.PREFIX + " docker=perhaps repo=no wrapper=no gh=no\\n"},
            {"code": 1}, {"lifecycle": "FAILED"}, {"plugin": "STOPPED"},
            {"shape": "VM.Standard.E4.Flex"},
        ):
            with self.subTest(options=options):
                sdk = HostSDK(**options)
                with self.assertRaises(cp.InventoryError):
                    capability.run(sdk, cp.config_from_env(sdk, ENV), pause=lambda _:None)
                if "shape" in options or "plugin" in options:
                    self.assertFalse(sdk.invocations)

    def test_rejects_any_edited_command(self):
        for value in ("", "sudo docker info", capability.COMMAND + "id\\n"):
            with self.assertRaises(cp.InventoryError):
                capability.fixed_command(value)

    def test_trusted_main_workflow_only(self):
        wf = (ROOT / ".github/workflows/oci-chronicles-boot-capabilities.yml").read_text()
        self.assertIn("github.event_name == 'push'", wf)
        self.assertIn("github.ref == 'refs/heads/main'", wf)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", wf)
        self.assertIn("contains(github.event.head_commit.message, 'one-shot Chronicles boot capability probe')", wf)
        self.assertIn("needs: contracts", wf)
        self.assertIn("cancel-in-progress: false", wf)
        self.assertNotIn("pull_request_target", wf)
        self.assertNotIn("docker compose up", wf)
        self.assertIn("python scripts/oci_chronicles_boot_capability.py run", wf)


if __name__ == "__main__":
    unittest.main()
