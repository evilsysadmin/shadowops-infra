"""Shared-host readiness must be measured, bounded and free of root mutations."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import cka_lab_host_preflight as hp
from test_oci_host_probe import HostSDK
from test_oci_control_plane import ENV
from oci_control_plane import config_from_env, InventoryError


def observation(**changes):
    value = dict.fromkeys(hp.FLAGS, True)
    value.update(schema=1, cpus=1, memory_total_mib=5900, memory_available_mib=3800,
                 disk_available_mib=25000, load_1m=0.2)
    value.update(changes)
    return value


def content(value=None):
    return NS(exit_code=0, text=hp.MARKER + json.dumps(value or observation()))


class SharedLabPreflight(unittest.TestCase):
    def test_fits_only_with_actual_memory_and_disk_headroom(self):
        value = hp.receipt("SUCCEEDED", content())
        self.assertTrue(value["resource_headroom"])
        self.assertFalse(value["pilot_enabled"])
        self.assertFalse(value["host_mutated"])
        for change in [{"memory_available_mib": 3071}, {"disk_available_mib": 12287}]:
            self.assertFalse(hp.receipt("SUCCEEDED", content(observation(**change)))["resource_headroom"])

    def test_insufficient_prerequisites_are_observed_not_changed(self):
        value = hp.receipt("SUCCEEDED", content(observation(rootless_dockerd=False, operator_sudo=False)))
        self.assertFalse(value["rootless_dockerd"])
        self.assertFalse(value["operator_sudo"])
        self.assertFalse(value["pilot_enabled"])

    def test_rejects_missing_text_failed_exit_and_extra_private_output(self):
        for state, result in [
            ("FAILED", content()), ("SUCCEEDED", NS(exit_code=None, text=content().text)),
            ("SUCCEEDED", NS(exit_code=True, text=content().text)),
            ("SUCCEEDED", NS(exit_code=0, text="")),
            ("SUCCEEDED", NS(exit_code=0, text=content().text + "\nprivate data")),
            ("SUCCEEDED", NS(exit_code=0, text="X" * 4097)),
        ]:
            with self.subTest(state=state), self.assertRaises(InventoryError):
                hp.receipt(state, result)

    def test_strict_schema_rejects_forged_or_impossible_capacity(self):
        for change in [{"schema": True}, {"schema": 2}, {"memory_available_mib": 6000},
                       {"memory_available_mib": True}, {"cpus": 0}, {"load_1m": float("nan")},
                       {"load_1m": float("inf")}, {"load_1m": -1}, {"operator_sudo": "yes"},
                       {"password": "must-never-print"}]:
            with self.subTest(change=change), self.assertRaises(InventoryError):
                hp.receipt("SUCCEEDED", content(observation(**change)))
        raw = content().text[:-1] + ',"schema":1}'
        with self.assertRaises(InventoryError):
            hp.receipt("SUCCEEDED", NS(exit_code=0, text=raw))

    def test_command_compiles_and_only_reads_existing_policy(self):
        compile(hp.PROBE, "<fixed-preflight>", "exec")
        for forbidden in ["sudo docker", "sudo bash", "docker.sock", "write_text", "os.environ", "systemctl restart"]:
            self.assertNotIn(forbidden, hp.COMMAND)
        self.assertIn("['sudo','--non-interactive','-l']", hp.COMMAND)

    def test_runs_exact_fixed_command_on_the_adopted_host(self):
        sdk = HostSDK(output=content().text)
        value = hp.execute(sdk, config_from_env(sdk, ENV), pause=lambda _: None)
        self.assertTrue(value["resource_headroom"])
        request = sdk.invocations[0][1]["create_instance_agent_command_details"].kwargs
        self.assertEqual(request["target"].kwargs["instance_id"], "instance-test")
        self.assertEqual(request["content"].kwargs["source"].kwargs["text"], hp.COMMAND)

    def test_wrong_host_or_unhealthy_agent_denies_before_submission(self):
        for change in [{"plugin": "STOPPED"}, {"shape": "VM.Standard.E4.Flex"}]:
            sdk = HostSDK(**change)
            with self.assertRaises(InventoryError):
                hp.execute(sdk, config_from_env(sdk, ENV), pause=lambda _: None)
            self.assertFalse(sdk.invocations)


if __name__ == "__main__":
    unittest.main()
