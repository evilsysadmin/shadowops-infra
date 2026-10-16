"""No PR execution of OCI APIs; verify the exact read-only Chronicles probe."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import oci_control_plane as cp
import oci_chronicles_ports_probe as probe
from test_oci_host_probe import HostSDK, ENV


class TestChroniclesPortsProbe(unittest.TestCase):
    def test_fixed_probe_targets_the_adopted_host(self):
        sdk = HostSDK(output=probe.READY + "\n")
        probe.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _: None)
        calls = [entry for entry in sdk.invocations if entry[0] == "create"]
        self.assertEqual(len(calls), 1)
        details = calls[0][1]["create_instance_agent_command_details"].kwargs
        self.assertEqual(details["target"].kwargs["instance_id"], "instance-test")
        remote = details["content"].kwargs["source"].kwargs["text"]
        self.assertEqual(remote, probe.COMMAND)
        self.assertIn("sport = :18081 or sport = :18082", remote)
        self.assertIn("test -z \"$listeners\"", remote)
        self.assertNotIn("sudo ", remote)
        self.assertNotIn("docker ps", remote)
        self.assertNotIn("docker compose up", remote)

    def test_refuse_missing_marker_failed_state_and_unsafe_host(self):
        for changed in ({"output": "wrong\n"}, {"output": probe.READY + "\nnoise"},
                        {"code": 1, "output": probe.READY}, {"lifecycle": "FAILED"},
                        {"plugin": "STOPPED"}, {"shape": "VM.Standard.E4.Flex"}):
            with self.subTest(changed=changed):
                sdk = HostSDK(output=probe.READY, **changed) if "output" not in changed else HostSDK(**changed)
                with self.assertRaises(cp.InventoryError):
                    probe.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _: None)
                if "plugin" in changed or "shape" in changed:
                    self.assertFalse(sdk.invocations)

    def test_refuse_any_operator_supplied_script(self):
        for bad in ("sudo docker ps", "", probe.COMMAND + "\ntrue",
                    "docker compose up -d", "echo $OCI_PRIVATE_KEY"):
            with self.subTest(bad=bad):
                with self.assertRaises(cp.InventoryError):
                    probe.assert_fixed_command(bad)

    def test_one_shot_oci_execution_requires_trusted_main(self):
        yaml = (ROOT / ".github/workflows/oci-chronicles-ports.yml").read_text()
        self.assertIn("github.event_name == 'workflow_dispatch'", yaml)
        self.assertIn("github.ref == 'refs/heads/main'", yaml)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", yaml)
        self.assertIn("needs: contracts", yaml)
        self.assertIn("cancel-in-progress: false", yaml)
        self.assertNotIn("pull_request_target", yaml)
        self.assertIn("(github.event_name == 'workflow_dispatch' || github.event_name == 'push')", yaml)
        self.assertIn("      - '.github/workflows/oci-chronicles-ports.yml'", yaml)
        self.assertIn("python scripts/oci_chronicles_ports_probe.py run", yaml)


if __name__ == "__main__":
    unittest.main()
