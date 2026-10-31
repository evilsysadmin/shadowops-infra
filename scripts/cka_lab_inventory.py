#!/usr/bin/env python3
"""Read-only capacity evidence for an isolated CKA staging runner.

Only the adopted hosting compartment is observed. No VM is created, resized,
started or selected for execution. Absence here says nothing about other
compartments, available quota, host capacity or Always Free eligibility.
"""
from __future__ import annotations

import json
import math
import os
import sys

from oci_control_plane import InventoryError, config_from_env, resolve_existing_host

RUNNER = "cka-lab-staging"


def capacity(instance):
    shape = getattr(instance, "shape_config", None)
    values = {}
    for field in ("ocpus", "memory_in_gbs"):
        value = getattr(shape, field, None)
        if (isinstance(value, bool) or not isinstance(value, (float, int))
                or not math.isfinite(value) or value <= 0):
            raise InventoryError("Missing or invalid OCI shape capacity")
        values[field] = value
    return values


def inspect(sdk, config):
    compartment, shared_id = resolve_existing_host(sdk, config)
    compute = sdk.core.ComputeClient(config)
    instances = sdk.pagination.list_call_get_all_results(
        compute.list_instances, compartment).data
    existing = [row for row in instances
                if row.lifecycle_state != "TERMINATED"]
    shared = [row for row in existing if row.id == shared_id]
    runners = [row for row in existing if row.display_name == RUNNER]
    if len(shared) != 1 or len(runners) > 1:
        raise InventoryError("Ambiguous CKA runner capacity inventory")
    if runners and runners[0].id == shared_id:
        raise InventoryError("CKA runner must be separate from the shared host")
    runner = {"present": False}
    if runners:
        row = runners[0]
        runner = {"present": True, "state": row.lifecycle_state,
                  "shape": row.shape, **capacity(row)}
    return {"schema": 1, "region": config["region"],
            "scope": "adopted-hosting-compartment-only",
            "existing_instances": len(existing),
            "shared_host": capacity(shared[0]),
            "dedicated_runner": runner,
            "lab_access_enabled": False}


def main():
    try:
        import oci
        report = inspect(oci, config_from_env(oci, os.environ))
    except Exception:
        # SDK exceptions can include private request identifiers. Never print
        # instance IDs, credentials, IPs, user data or full SDK responses.
        print("CKA_LAB_INVENTORY_BLOCKED: read-only capacity unavailable", file=sys.stderr)
        return 1
    print("CKA_LAB_CAPACITY " + json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
