#!/usr/bin/env python3
"""Read-only tenancy-wide capacity preflight for the Always Free CKA runner.

This is capacity evidence, not an allocator, a billing receipt or a lab grant.
Every compartment must be enumerable: a permission/API error is never zero use.
"""
from __future__ import annotations

import json
import math
import os
import sys

from cka_lab_inventory import RUNNER, capacity
from oci_control_plane import InventoryError, SHAPE, config_from_env, resolve_existing_host

# Conservative current published Always Free envelope, not the historical 4/24.
# https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
MAX_OCPUS = 2
MAX_MEMORY_GB = 12
MAX_STORAGE_GB = 200
RUNNER_OCPUS = 1
RUNNER_MEMORY_GB = 6
RUNNER_BOOT_GB = 50
A1_SHAPES = {SHAPE, "BM.Standard.A1.160", "CI.Standard.A1.Flex"}


def rows(sdk, method, *args, **kwargs):
    data = sdk.pagination.list_call_get_all_results(method, *args, **kwargs).data
    if not isinstance(data, list):
        data = getattr(data, "items", None)
    if not isinstance(data, list):
        raise InventoryError("Incomplete OCI inventory collection")
    return data


def identifier(value):
    identity = getattr(value, "id", None)
    if not isinstance(identity, str) or not identity:
        raise InventoryError("Missing inventory identity")
    return identity


def active(value):
    state = getattr(value, "lifecycle_state", None)
    if not isinstance(state, str) or not state:
        raise InventoryError("Missing inventory lifecycle")
    return state not in {"TERMINATED", "DELETED"}


def inspect(sdk, config):
    tenancy = config["tenancy"]
    identity = sdk.identity.IdentityClient(config)
    regions = rows(sdk, identity.list_region_subscriptions, tenancy)
    home = [r for r in regions if getattr(r, "is_home_region", None) is True]
    if (len(home) != 1 or home[0].region_name != config["region"]
            or getattr(home[0], "status", None) != "READY"):
        raise InventoryError("CKA Always Free runner requires the ready home region")

    # ANY is intentional: ACCESSIBLE could silently omit billed resources in
    # inaccessible compartments. Enumerating their resources must also succeed.
    compartments = rows(sdk, identity.list_compartments, tenancy,
                        access_level="ANY", compartment_id_in_subtree=True)
    ids = [tenancy]
    for compartment in compartments:
        if active(compartment):
            key = identifier(compartment)
            if key in ids:
                raise InventoryError("Ambiguous compartment inventory")
            ids.append(key)
    domains = rows(sdk, identity.list_availability_domains, tenancy)
    domain_names = [getattr(d, "name", None) for d in domains]
    if (not domain_names or any(not isinstance(n, str) or not n for n in domain_names)
            or len(set(domain_names)) != len(domain_names)):
        raise InventoryError("Incomplete availability-domain inventory")

    adopted_compartment, shared_id = resolve_existing_host(sdk, config)
    if adopted_compartment not in ids:
        raise InventoryError("Adopted compartment absent from full inventory")
    compute = sdk.core.ComputeClient(config)
    containers = sdk.container_instances.ContainerInstanceClient(config)
    storage = sdk.core.BlockstorageClient(config)
    seen = set()
    used = {"ocpus": 0, "memory_in_gbs": 0, "storage_gbs": 0}
    runner = []
    shared = []

    def unique(item):
        key = identifier(item)
        if key in seen:
            raise InventoryError("Duplicate resource in full inventory")
        seen.add(key)
        return key

    for compartment in ids:
        for method in (compute.list_instances, containers.list_container_instances):
            for instance in rows(sdk, method, compartment_id=compartment):
                if not active(instance):
                    continue
                key = unique(instance)
                if key == shared_id:
                    shared.append(instance)
                if getattr(instance, "display_name", None) == RUNNER:
                    runner.append((compartment, instance))
                shape = getattr(instance, "shape", None)
                if not isinstance(shape, str) or not shape:
                    raise InventoryError("Missing compute shape")
                if "A1" in shape:
                    if shape not in A1_SHAPES:
                        raise InventoryError("Unknown A1 capacity consumer")
                    size = capacity(instance)
                    used["ocpus"] += size["ocpus"]
                    used["memory_in_gbs"] += size["memory_in_gbs"]
        volumes = rows(sdk, storage.list_volumes, compartment_id=compartment)
        for domain in domain_names:
            volumes.extend(rows(sdk, storage.list_boot_volumes,
                                availability_domain=domain, compartment_id=compartment))
        for volume in volumes:
            if not active(volume):
                continue
            unique(volume)
            size = getattr(volume, "size_in_gbs", None)
            if (isinstance(size, bool) or not isinstance(size, (int, float))
                    or not math.isfinite(size) or size <= 0 or int(size) != size):
                raise InventoryError("Invalid volume capacity")
            used["storage_gbs"] += int(size)

    if len(shared) != 1 or shared[0].shape != SHAPE or len(runner) > 1:
        raise InventoryError("Ambiguous shared or runner identity")
    if runner:
        compartment, existing = runner[0]
        if (compartment != adopted_compartment or identifier(existing) == shared_id
                or existing.shape != SHAPE
                or capacity(existing) != {"ocpus": RUNNER_OCPUS, "memory_in_gbs": RUNNER_MEMORY_GB}):
            raise InventoryError("Existing CKA runner does not match the fixed free pilot")
    proposed = {"shape": SHAPE, "ocpus": RUNNER_OCPUS,
                "memory_in_gbs": RUNNER_MEMORY_GB, "boot_volume_gbs": RUNNER_BOOT_GB}
    projected = dict(used)
    if not runner:
        projected["ocpus"] += RUNNER_OCPUS
        projected["memory_in_gbs"] += RUNNER_MEMORY_GB
        projected["storage_gbs"] += RUNNER_BOOT_GB
    limits = {"ocpus": MAX_OCPUS, "memory_in_gbs": MAX_MEMORY_GB, "storage_gbs": MAX_STORAGE_GB}
    blockers = [key for key, maximum in limits.items() if projected[key] > maximum]
    return {"schema": 1, "region": config["region"], "scope": "home-region-all-compartments",
            "compartments_observed": len(ids), "always_free_only": True,
            "limits": limits, "used": used, "proposed_runner": proposed,
            "projected": projected, "runner_present": bool(runner),
            "fits_free_capacity": not blockers, "capacity_blockers": blockers,
            "allocation_performed": False, "lab_access_enabled": False}


def main():
    try:
        import oci
        result = inspect(oci, config_from_env(oci, os.environ))
    except Exception:
        # Provider errors can contain OCIDs, request details and IP addresses.
        print("CKA_ALWAYS_FREE_CAPACITY_BLOCKED: complete inventory unavailable", file=sys.stderr)
        return 1
    print("CKA_ALWAYS_FREE_CAPACITY " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
