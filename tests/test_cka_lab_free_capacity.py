"""Always Free decisions using read-only synthetic OCI inventory responses."""
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cka_lab_free_capacity as free

CONFIG = {"tenancy": "private-tenancy", "region": "eu-frankfurt-1"}


def instance(key="shared", *, name="shared-name", ocpus=1, memory=6, state="RUNNING", shape=free.SHAPE):
    return NS(id=key, display_name=name, shape=shape, lifecycle_state=state,
              shape_config=NS(ocpus=ocpus, memory_in_gbs=memory))


def volume(key="shared-boot", size=50, state="AVAILABLE"):
    return NS(id=key, size_in_gbs=size, lifecycle_state=state)


class Inventory:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.data = {
            "regions": [NS(region_name=CONFIG["region"], is_home_region=True, status="READY")],
            "compartments": [NS(id="adopted", lifecycle_state="ACTIVE"), NS(id="other", lifecycle_state="ACTIVE")],
            "domains": [NS(name="ad-one"), NS(name="ad-two")],
            ("compute", "adopted"): [instance()],
            ("boot", "adopted", "ad-one"): [volume()],
        }

        def method(label):
            def read(*args, **kwargs):
                self.calls.append((label, args, kwargs))
                if label in {"regions", "compartments", "domains"}:
                    key = label
                elif label == "boot":
                    key = (label, kwargs["compartment_id"], kwargs["availability_domain"])
                else:
                    key = (label, kwargs["compartment_id"])
                if self.failure == key:
                    raise RuntimeError("private OCI detail must not leak")
                value = copy.deepcopy(self.data.get(key, []))
                return NS(data=NS(items=value) if label == "containers" else value)
            return read

        identity = NS(list_region_subscriptions=method("regions"), list_compartments=method("compartments"),
                      list_availability_domains=method("domains"))
        compute = NS(list_instances=method("compute"))
        containers = NS(list_container_instances=method("containers"))
        storage = NS(list_volumes=method("block"), list_boot_volumes=method("boot"))
        self.sdk = NS(identity=NS(IdentityClient=lambda _: identity),
                      core=NS(ComputeClient=lambda _: compute, BlockstorageClient=lambda _: storage),
                      container_instances=NS(ContainerInstanceClient=lambda _: containers),
                      pagination=NS(list_call_get_all_results=lambda f, *args, **kw: f(*args, **kw)))

    def inspect(self):
        with patch.object(free, "resolve_existing_host", return_value=("adopted", "shared")):
            return free.inspect(self.sdk, CONFIG)


class AlwaysFreeCapacity(unittest.TestCase):
    def test_fixed_small_runner_fits_the_current_two_cpu_envelope(self):
        inv = Inventory()
        value = inv.inspect()
        self.assertTrue(value["fits_free_capacity"])
        self.assertEqual(value["projected"], {"ocpus": 2, "memory_in_gbs": 12, "storage_gbs": 100})
        self.assertFalse(value["allocation_performed"])
        self.assertFalse(value["lab_access_enabled"])
        query = next(c for c in inv.calls if c[0] == "compartments")
        self.assertEqual(query[2], {"access_level": "ANY", "compartment_id_in_subtree": True})

    def test_root_other_compartments_containers_and_all_domains_are_counted(self):
        inv = Inventory()
        inv.data[("compute", "private-tenancy")] = [instance("root-vm")]
        inv.data[("containers", "other")] = [instance("container", shape="CI.Standard.A1.Flex")]
        inv.data[("boot", "other", "ad-two")] = [volume("other-boot", 70)]
        inv.data[("block", "private-tenancy")] = [volume("detached-volume", 50)]
        value = inv.inspect()
        self.assertEqual(value["used"], {"ocpus": 3, "memory_in_gbs": 18, "storage_gbs": 170})
        self.assertEqual(set(value["capacity_blockers"]), {"ocpus", "memory_in_gbs", "storage_gbs"})

    def test_stopped_and_terminating_resources_reserve_capacity(self):
        for state in ["STOPPED", "STOPPING", "TERMINATING"]:
            inv = Inventory()
            inv.data[("compute", "other")] = [instance("other-vm", state=state)]
            inv.data[("block", "other")] = [volume("old-volume", 101, "TERMINATING")]
            value = inv.inspect()
            self.assertFalse(value["fits_free_capacity"])
            self.assertEqual(value["used"]["ocpus"], 2)
            self.assertEqual(value["used"]["storage_gbs"], 151)

    def test_terminated_resources_do_not_consume_capacity(self):
        inv = Inventory()
        inv.data[("compute", "other")] = [instance("gone", state="TERMINATED")]
        inv.data[("block", "other")] = [volume("gone-volume", 200, "TERMINATED")]
        self.assertTrue(inv.inspect()["fits_free_capacity"])

    def test_existing_exact_runner_does_not_add_a_second_allocation(self):
        inv = Inventory()
        inv.data[("compute", "adopted")].append(instance("runner", name=free.RUNNER))
        inv.data[("boot", "adopted", "ad-two")] = [volume("runner-boot")]
        value = inv.inspect()
        self.assertTrue(value["runner_present"])
        self.assertTrue(value["fits_free_capacity"])
        self.assertEqual(value["projected"], value["used"])

    def test_runner_cannot_adopt_foreign_wrong_size_or_shared_host(self):
        for compartment, row in [
            ("other", instance("runner", name=free.RUNNER)),
            ("adopted", instance("runner", name=free.RUNNER, ocpus=2)),
            ("adopted", instance("runner", name=free.RUNNER, shape="VM.Standard.E4.Flex")),
        ]:
            inv = Inventory()
            inv.data[("compute", compartment)] = inv.data.get(("compute", compartment), []) + [row]
            with self.assertRaises(free.InventoryError):
                inv.inspect()
        inv = Inventory()
        inv.data[("compute", "adopted")][0].display_name = free.RUNNER
        with self.assertRaises(free.InventoryError):
            inv.inspect()

    def test_missing_permissions_are_never_zero_usage(self):
        for endpoint in [("compute", "other"), ("containers", "private-tenancy"),
                         ("boot", "other", "ad-two"), ("block", "private-tenancy")]:
            inv = Inventory()
            inv.failure = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(RuntimeError):
                inv.inspect()

    def test_wrong_or_unknown_home_region_denies_before_resource_queries(self):
        for changes in [{"region_name": "us-ashburn-1"}, {"status": "IN_PROGRESS"}, {"is_home_region": False}]:
            inv = Inventory()
            inv.data["regions"] = [NS(**{**vars(inv.data["regions"][0]), **changes})]
            with self.assertRaises(free.InventoryError):
                inv.inspect()
            self.assertEqual([c[0] for c in inv.calls], ["regions"])

    def test_ambiguous_or_partial_inventory_denies(self):
        edits = [
            ("compartments", [NS(id="private-tenancy", lifecycle_state="ACTIVE")]),
            ("domains", []), ("domains", [NS(name="same"), NS(name="same")]),
            (("compute", "other"), [instance()]), (("compute", "adopted"), []),
            (("compute", "other"), [instance("mystery", shape="unknown-A1-shape")]),
        ]
        for key, value in edits:
            inv = Inventory()
            inv.data[key] = value
            with self.subTest(key=key), self.assertRaises(free.InventoryError):
                inv.inspect()

    def test_invalid_capacity_never_reports_free_eligibility(self):
        for bad in [None, True, -1, 0, float("inf"), float("nan"), "50", 50.5]:
            inv = Inventory()
            inv.data[("block", "other")] = [volume("bad", bad)]
            with self.subTest(size=bad), self.assertRaises(free.InventoryError):
                inv.inspect()
        for bad in [None, True, -1, 0, float("inf"), float("nan"), "1"]:
            inv = Inventory()
            inv.data[("compute", "other")] = [instance("bad", ocpus=bad)]
            with self.subTest(ocpus=bad), self.assertRaises(free.InventoryError):
                inv.inspect()

    def test_storage_alone_can_block_the_runner(self):
        inv = Inventory()
        inv.data[("block", "other")] = [volume("unused-but-billed", 101)]
        self.assertEqual(inv.inspect()["capacity_blockers"], ["storage_gbs"])

    def test_report_does_not_disclose_resource_identifiers_or_names(self):
        value = json.dumps(Inventory().inspect())
        for private in ["private-tenancy", "adopted", "other", "shared-name", "shared-boot"]:
            self.assertNotIn(private, value)

    def test_failure_output_is_sanitized(self):
        with patch.dict(sys.modules, {"oci": NS()}), patch.object(free, "config_from_env", return_value=CONFIG), \
                patch.object(free, "inspect", side_effect=RuntimeError("private-credentials-and-IP")), \
                patch("sys.stderr", new_callable=io.StringIO) as output:
            self.assertEqual(free.main(), 1)
        self.assertNotIn("private-credentials-and-IP", output.getvalue())


if __name__ == "__main__":
    unittest.main()
