"""Only the fixed read-only rootless wrapper may be inspected over OCI."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import cka_lab_runtime_inspect as runtime
from test_oci_host_probe import HostSDK
from test_oci_control_plane import ENV
from oci_control_plane import InventoryError, config_from_env

def evidence(**changes):
    value = {"schema": 1, "source_sha": "a" * 40, "runtime": "dedicated-rootless-user",
             "disk_bytes": 8 * 1024**3, "rootless_and_cgroups_verified": True,
             "kubernetes_started": False, "labs_enabled": False}
    value.update(changes)
    return value

def output(value=None):
    return runtime.MARKER + json.dumps(evidence() if value is None else value) + "\n"

class ReadOnlyInstalledRuntime(unittest.TestCase):
    def test_receipt_requires_exact_installed_rootless_contract(self):
        valid = runtime.receipt("SUCCEEDED", NS(text=output(), exit_code=0))
        self.assertEqual(valid["source_sha"], "a" * 40)
        self.assertTrue(valid["inspection_only"])
        self.assertFalse(valid["labs_enabled"])
        for change in ({"schema": True}, {"source_sha": "X" * 40}, {"source_sha": "a" * 39},
                       {"runtime": "rootful"}, {"disk_bytes": True}, {"disk_bytes": 0},
                       {"rootless_and_cgroups_verified": 1}, {"kubernetes_started": True},
                       {"labs_enabled": True}, {"secret": "do-not-print"}):
            with self.subTest(change=change), self.assertRaises(InventoryError):
                runtime.receipt("SUCCEEDED", NS(text=output(evidence(**change)), exit_code=0))

    def test_fail_closed_on_missing_duplicate_or_unverified_stdout(self):
        duplicated = output()[:-2] + ',"schema":1}\n'
        for status, code, text in (
            ("FAILED", 0, output()), ("SUCCEEDED", None, output()),
            ("SUCCEEDED", False, output()), ("SUCCEEDED", True, output()),
            ("SUCCEEDED", "0", output()), ("SUCCEEDED", 1, output()),
            ("SUCCEEDED", 0, "SECRET\n" + output()), ("SUCCEEDED", 0, output() + "SECRET"),
            ("SUCCEEDED", 0, duplicated), ("SUCCEEDED", 0, ""),
            ("SUCCEEDED", 0, "X" * 1025)):
            with self.subTest(status=status, code=code, raw=str(text)[:40]), self.assertRaises(InventoryError):
                runtime.receipt(status, NS(exit_code=code, text=text))

    def test_fixed_authority_only_and_single_adopted_host(self):
        self.assertEqual(runtime.COMMAND, "set -eu\nsudo -n /usr/local/sbin/shadowops-cka-lab-staging inspect\n")
        for bad in ("docker ", "git ", "install ", "bash ", "sh -c", "compose ", "sudo -i"):
            self.assertNotIn(bad, runtime.COMMAND)
        sdk = HostSDK(output=output())
        result = runtime.execute(sdk, config_from_env(sdk, ENV), pause=lambda _: None)
        self.assertTrue(result["inspection_only"])
        self.assertEqual([name for name, _ in sdk.observed], ["validate", "list", "list", "plugin"])
        self.assertEqual(len(sdk.invocations), 2)
        body = sdk.invocations[0][1]["create_instance_agent_command_details"].kwargs
        self.assertEqual(body["target"].kwargs["instance_id"], "instance-test")
        self.assertEqual(body["content"].kwargs["source"].kwargs["text"], runtime.COMMAND)

    def test_unhealthy_host_or_missing_sudo_grant_refuses_inspection(self):
        for changes in ({"shape": "VM.Standard.E4.Flex"},
                        {"plugin": "STOPPED"}, {"lifecycle": "FAILED"},
                        {"code": 1}, {"output": "sudo: permission denied\n"}):
            sdk = HostSDK(**changes)
            with self.subTest(changes=changes), self.assertRaises(InventoryError):
                runtime.execute(sdk, config_from_env(sdk, ENV), pause=lambda _: None)
            if "shape" in changes or "plugin" in changes:
                self.assertEqual(sdk.invocations, [])

if __name__ == "__main__":
    unittest.main()
