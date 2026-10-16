#!/usr/bin/env python3
"""ShadowOps OCI control plane: read-only observation of the EXISTING A1.

No provisioning, no Run Command execution, no shell, no writes, no OCI state.
The inventory pins the adopted host identity; it cannot target an arbitrary
instance selected by a workflow caller. Fail closed on ambiguity.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Mapping

COMPARTMENT = "chess-studio-staging"
INSTANCE = "chess-studio-staging"
SHAPE = "VM.Standard.A1.Flex"
PLUGIN = "Compute Instance Run Command"
DEFAULT_REGION = "eu-frankfurt-1"
NEEDED = ("OCI_TENANCY_OCID", "OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY")


class InventoryError(Exception):
    pass


def config_from_env(sdk: Any, env: Mapping[str, str]) -> dict[str, str]:
    absent = [name for name in NEEDED if not env.get(name, "").strip()]
    if absent:
        raise InventoryError("OCI Actions credentials incomplete: missing " + ", ".join(absent))
    region = env.get("OCI_REGION", DEFAULT_REGION).strip() or DEFAULT_REGION
    if not region.replace("-", "").isalnum():
        raise InventoryError("OCI region format invalid")
    config = {
        "tenancy": env["OCI_TENANCY_OCID"].strip(),
        "user": env["OCI_USER_OCID"].strip(),
        "fingerprint": env["OCI_FINGERPRINT"].strip(),
        "key_content": env["OCI_PRIVATE_KEY"].replace("\r", ""),
        "region": region,
    }
    try:
        sdk.config.validate_config(config)
    except Exception as exc:
        raise InventoryError("OCI credential structure validation failed") from exc
    return config


def _one(rows: Any, *, label: str) -> Any:
    entries = list(rows)
    if len(entries) != 1:
        raise InventoryError(f"Expected one active {label}; found {len(entries)}")
    return entries[0]


def resolve_existing_host(sdk: Any, config: dict[str, str]) -> tuple[str, str]:
    """Resolve exactly the adopted A1; never an operator-provided host."""
    identity = sdk.identity.IdentityClient(config)
    compartments = sdk.pagination.list_call_get_all_results(
        identity.list_compartments,
        config["tenancy"],
        access_level="ACCESSIBLE",
        compartment_id_in_subtree=True,
        name=COMPARTMENT,
        lifecycle_state="ACTIVE",
    ).data
    compartment = _one(
        (item for item in compartments if item.name == COMPARTMENT),
        label="OCI hosting compartment",
    )
    compute = sdk.core.ComputeClient(config)
    instances = sdk.pagination.list_call_get_all_results(
        compute.list_instances,
        compartment.id,
        display_name=INSTANCE,
        lifecycle_state="RUNNING",
    ).data
    instance = _one(
        (item for item in instances if item.display_name == INSTANCE),
        label="OCI hosting A1",
    )
    if instance.shape != SHAPE or instance.lifecycle_state != "RUNNING":
        raise InventoryError("Adopted OCI host shape or lifecycle mismatch")
    return str(compartment.id), str(instance.id)


def inspect(sdk: Any, config: dict[str, str]) -> dict[str, str]:
    compartment_id, instance_id = resolve_existing_host(sdk, config)
    agent = sdk.compute_instance_agent.PluginClient(config)
    response = agent.get_instance_agent_plugin(
        instanceagent_id=instance_id,
        compartment_id=compartment_id,
        plugin_name=PLUGIN,
        retry_strategy=sdk.retry.DEFAULT_RETRY_STRATEGY,
    ).data
    status = str(getattr(response, "status", "UNKNOWN") or "UNKNOWN").upper()
    if status != "RUNNING":
        raise InventoryError("OCI Run Command plugin not healthy")
    return {
        "region": config["region"],
        "instance": INSTANCE,
        "shape": SHAPE,
        "run_command": "RUNNING",
    }


def self_test() -> None:
    assert COMPARTMENT == "chess-studio-staging"
    assert INSTANCE == "chess-studio-staging"
    assert SHAPE == "VM.Standard.A1.Flex"
    assert set(NEEDED) == {
        "OCI_TENANCY_OCID", "OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY"
    }
    try:
        _one([], label="test")
    except InventoryError:
        pass
    else:
        raise AssertionError("Missing resource accepted")
    print("SHADOWOPS_OCI_INVENTORY_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "self-test"))
    args = parser.parse_args()
    if args.operation == "self-test":
        self_test()
        return 0
    try:
        import oci
    except ImportError:
        print("SHADOWOPS_OCI_INVENTORY_BLOCKED: OCI SDK not installed", file=sys.stderr)
        return 1
    try:
        result = inspect(oci, config_from_env(oci, os.environ))
    except InventoryError as exc:
        print("SHADOWOPS_OCI_INVENTORY_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("SHADOWOPS_OCI_INVENTORY_BLOCKED: OCI request failed (" + type(exc).__name__ + ")", file=sys.stderr)
        return 1
    print("SHADOWOPS_OCI_INVENTORY_OK " + " ".join(f"{k}={v}" for k, v in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
