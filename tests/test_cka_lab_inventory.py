"""Observe capacity without selecting any machine for lab execution."""
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cka_lab_inventory as inv


def instance(name="chess-studio-staging", identity="shared", state="RUNNING"):
    return NS(id=identity, display_name=name, lifecycle_state=state,
              shape="VM.Standard.A1.Flex",
              shape_config=NS(ocpus=4.0, memory_in_gbs=24.0))


class InventoryTest(unittest.TestCase):
    def inspect(self, rows):
        self.calls = []
        def listing(*args, **kwargs):
            self.calls.append((args, kwargs))
            return NS(data=rows)
        compute = NS(list_instances=object())
        sdk = NS(core=NS(ComputeClient=lambda config: compute),
                 pagination=NS(list_call_get_all_results=listing))
        with patch.object(inv, "resolve_existing_host", return_value=("adopted", "shared")):
            report = inv.inspect(sdk, {"region": "eu-frankfurt-1"})
        self.assertEqual(self.calls, [((compute.list_instances, "adopted"), {})])
        return report

    def test_absent_runner_does_not_repurpose_shared_host(self):
        report = self.inspect([instance()])
        self.assertEqual(report["dedicated_runner"], {"present": False})
        self.assertEqual(report["shared_host"], {"ocpus": 4, "memory_in_gbs": 24})
        self.assertFalse(report["lab_access_enabled"])
        self.assertNotIn("shared", report.values())

    def test_observe_stopped_runner_without_starting_it(self):
        report = self.inspect([instance(), instance(inv.RUNNER, "dedicated", "STOPPED")])
        self.assertEqual(report["dedicated_runner"]["state"], "STOPPED")
        self.assertEqual(report["existing_instances"], 2)

    def test_terminated_runner_is_not_available(self):
        report = self.inspect([instance(), instance(inv.RUNNER, "old", "TERMINATED")])
        self.assertFalse(report["dedicated_runner"]["present"])

    def test_ambiguous_or_relabelled_hosts_fail_closed(self):
        for rows in ([], [instance(inv.RUNNER)],
                     [instance(), instance(inv.RUNNER, "one"), instance(inv.RUNNER, "two")]):
            with self.subTest(rows=rows), self.assertRaises(inv.InventoryError):
                self.inspect(rows)

    def test_missing_nonfinite_negative_capacity_rejected(self):
        for bad in (None, True, -1, 0, float("inf"), float("nan"), "24"):
            row = instance()
            row.shape_config.memory_in_gbs = bad
            with self.subTest(value=bad), self.assertRaises(inv.InventoryError):
                self.inspect([row])


if __name__ == "__main__":
    unittest.main()
